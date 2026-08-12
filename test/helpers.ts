/**
 * Shared test helpers.
 *
 * `decryptAes128gcm` re-implements the RFC 8291 / RFC 8188 receiver side
 * INDEPENDENTLY of `src/send.ts` (its own HKDF chain, not a call into the
 * library) so that the round-trip test is a genuine cross-check of the
 * ciphertext, not a mirror of the implementation. Base64url en/decoding reuses
 * the library codec, which is verified on its own in `vapid.test.ts`.
 */

import { Mock, vi } from "vite-plus/test";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "../src/vapid";

/** Stub global `fetch` to resolve with the given response; returns the mock. */
export const stubFetch = (
	status = 201,
	statusText = "",
	headers?: Record<string, string>,
): Mock<(_input: string | URL | Request, _init?: RequestInit) => Promise<Response>> => {
	// 204/304/1xx must be constructed with a null body or Response throws.
	const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);
	// The explicit type parameter keeps `mock.calls` a two-element tuple; without
	// it the tuple types as empty and every `calls[0][1]` fails to compile.
	const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
		async () => new Response(noBody ? null : "err-body", { status, statusText, headers }),
	);
	vi.stubGlobal("fetch", mock);
	return mock;
};

/** The headers of the first `fetch` call, as the plain record the library passes. */
export const headersOf = (mock: ReturnType<typeof stubFetch>): Record<string, string> =>
	(mock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;

/**
 * A simulated browser subscription: the public `p256dh`/`auth` a server sees,
 * plus the private material only the test holds.
 */
export type ClientKeys = {
	/** Raw uncompressed P-256 public key, URL-safe base64 (the `p256dh`). */
	p256dh: string;
	/** 16-byte auth secret, URL-safe base64. */
	auth: string;
	/** Raw client public key bytes (needed to rebuild the HKDF `info`). */
	publicKeyBytes: Uint8Array;
	/** ECDH private key for deriving the shared secret during decryption. */
	privateKey: CryptoKey;
};

/**
 * Generate a realistic browser-side subscription keypair: an ECDH P-256 key
 * (exported raw as `p256dh`) plus a random 16-byte auth secret.
 */
export const makeClientKeys = async (): Promise<ClientKeys> => {
	const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
		"deriveBits",
	]);
	const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
	const auth = crypto.getRandomValues(new Uint8Array(16));
	return {
		p256dh: uint8ArrayToUrlBase64(rawPub),
		auth: uint8ArrayToUrlBase64(auth),
		publicKeyBytes: rawPub,
		privateKey: keyPair.privateKey,
	};
};

// Return type is not bare `Uint8Array`: that widens to `ArrayBufferLike`, which
// WebCrypto's `BufferSource` rejects.
const concat = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> => {
	const total = parts.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const p of parts) {
		out.set(p, offset);
		offset += p.length;
	}
	return out;
};

type Aes128gcmBody = {
	salt: Uint8Array<ArrayBuffer>;
	serverPublicKey: Uint8Array<ArrayBuffer>;
	ciphertext: Uint8Array<ArrayBuffer>;
};

/** Split a body into `salt | rs | idlen | keyid | ciphertext` — RFC 8188 §2.1. */
const parseAes128gcmBody = (body: Uint8Array): Aes128gcmBody => {
	const idlen = body[20];
	return {
		salt: body.slice(0, 16),
		serverPublicKey: body.slice(21, 21 + idlen),
		ciphertext: body.slice(21 + idlen),
	};
};

const deriveSharedSecret = async (
	serverPublicKeyBytes: Uint8Array<ArrayBuffer>,
	clientPrivateKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> => {
	const serverPublicKey = await crypto.subtle.importKey(
		"raw",
		serverPublicKeyBytes,
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		[],
	);
	return new Uint8Array(
		await crypto.subtle.deriveBits(
			{ name: "ECDH", public: serverPublicKey },
			clientPrivateKey,
			256,
		),
	);
};

/** `label || 0x00 || context`, the HKDF info construction of RFC 8291 §3.4. */
const hkdfInfo = (label: string, ...context: Uint8Array[]): Uint8Array<ArrayBuffer> =>
	concat(new TextEncoder().encode(label), new Uint8Array([0x00]), ...context);

/** PRK = HKDF(salt = auth_secret, IKM = ECDH shared secret) — RFC 8291 §3.4. */
const deriveInputKeyingMaterial = async (
	sharedSecret: Uint8Array<ArrayBuffer>,
	authSecret: Uint8Array<ArrayBuffer>,
	clientPublicKey: Uint8Array,
	serverPublicKey: Uint8Array,
): Promise<CryptoKey> => {
	const sharedKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, [
		"deriveBits",
	]);
	const ikm = new Uint8Array(
		await crypto.subtle.deriveBits(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: authSecret,
				info: hkdfInfo("WebPush: info", clientPublicKey, serverPublicKey),
			},
			sharedKey,
			256,
		),
	);
	return crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits", "deriveKey"]);
};

const deriveContentEncryptionKey = (
	ikmKey: CryptoKey,
	salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> =>
	crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt, info: hkdfInfo("Content-Encoding: aes128gcm") },
		ikmKey,
		{ name: "AES-GCM", length: 128 },
		false,
		["decrypt"],
	);

const deriveNonce = async (
	ikmKey: CryptoKey,
	salt: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> =>
	new Uint8Array(
		await crypto.subtle.deriveBits(
			{ name: "HKDF", hash: "SHA-256", salt, info: hkdfInfo("Content-Encoding: nonce") },
			ikmKey,
			96,
		),
	);

/** @throws {Error} if the plaintext does not end in the RFC 8188 `0x02` delimiter. */
const stripPaddingDelimiter = (padded: Uint8Array): Uint8Array => {
	const delimiterIndex = padded.length - 1;
	if (padded[delimiterIndex] !== 0x02) {
		throw new Error(`unexpected padding delimiter: ${padded[delimiterIndex]}`);
	}
	return padded.slice(0, delimiterIndex);
};

/**
 * Decrypt an aes128gcm Web Push body (RFC 8188 header + RFC 8291 key schedule)
 * back to the original plaintext bytes.
 *
 * @param body - The full encrypted request body, header included
 * @param clientKeys - The recipient keys produced by {@link makeClientKeys}
 * @throws {Error} if the GCM tag fails or the plaintext lacks the 0x02 delimiter.
 */
export const decryptAes128gcm = async (
	body: Uint8Array,
	clientKeys: ClientKeys,
): Promise<Uint8Array> => {
	const { salt, serverPublicKey, ciphertext } = parseAes128gcmBody(body);
	const sharedSecret = await deriveSharedSecret(serverPublicKey, clientKeys.privateKey);
	const ikmKey = await deriveInputKeyingMaterial(
		sharedSecret,
		urlBase64ToUint8Array(clientKeys.auth),
		clientKeys.publicKeyBytes,
		serverPublicKey,
	);
	const contentEncryptionKey = await deriveContentEncryptionKey(ikmKey, salt);
	const nonce = await deriveNonce(ikmKey, salt);

	return stripPaddingDelimiter(
		new Uint8Array(
			await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, contentEncryptionKey, ciphertext),
		),
	);
};

/** Decode a base64url JWT segment to a parsed JSON object. */
export const decodeJwtSegment = (segment: string): Record<string, unknown> => {
	const bytes = urlBase64ToUint8Array(segment);
	return JSON.parse(new TextDecoder().decode(bytes));
};

/** Verify a JWT's ES256 signature against a URL-safe base64 P-256 public key. */
export const verifyJwtSignature = async (jwt: string, publicKey: string): Promise<boolean> => {
	const [header, claims, signature] = jwt.split(".");
	const verifyKey = await crypto.subtle.importKey(
		"raw",
		urlBase64ToUint8Array(publicKey),
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["verify"],
	);
	return crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		verifyKey,
		urlBase64ToUint8Array(signature),
		new TextEncoder().encode(`${header}.${claims}`),
	);
};
