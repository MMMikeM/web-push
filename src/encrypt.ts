/**
 * aes128gcm content encryption for Web Push (RFC 8291 / RFC 8188).
 *
 * Split out from the HTTP/VAPID orchestration in `send.ts` so the encryption
 * core can be unit-tested in isolation. This module is deliberately NOT a
 * package entry point (see the `exports` map in package.json): `encryptRecord`
 * is reachable only from inside the bundle and from tests that import `src/`
 * directly — never by consumers of the published package.
 */

import { urlBase64ToUint8Array } from "./vapid";

const SALT_LENGTH = 16;
const RECORD_SIZE_LENGTH = 4;
const ID_LENGTH_LENGTH = 1;
const KEY_ID_LENGTH = 65;
const GCM_TAG_LENGTH = 16;
const PADDING_DELIMITER = 0x02;
const UNCOMPRESSED_POINT_TAG = 0x04;

/** aes128gcm content-coding header length, 86 octets (RFC 8188 §2.1). */
const HEADER_LENGTH = SALT_LENGTH + RECORD_SIZE_LENGTH + ID_LENGTH_LENGTH + KEY_ID_LENGTH;

/**
 * Record size advertised in the header. Also the ceiling a push service is
 * required to accept for the *whole* request body (RFC 8291 §4 / RFC 8030 §7.2).
 */
const RECORD_SIZE = 4096;

/**
 * Largest plaintext that fits in a single record without pushing the request
 * body past {@link RECORD_SIZE}: the body is the header plus the encrypted
 * record (plaintext + padding delimiter + GCM tag). 3993 octets (RFC 8291 §4).
 */
const MAX_PAYLOAD_BYTES = RECORD_SIZE - HEADER_LENGTH - 1 - GCM_TAG_LENGTH;

const encoder = new TextEncoder();

/**
 * Split from {@link validatePushInputs} so a batch send can reject an
 * oversized payload once, up front, rather than once per subscription.
 *
 * @throws {Error} if the payload exceeds the single-record limit.
 */
export const assertPayloadWithinLimit = (payload: Uint8Array): void => {
	if (payload.length > MAX_PAYLOAD_BYTES) {
		throw new Error(
			`Payload too large: ${payload.length} bytes exceeds the ${MAX_PAYLOAD_BYTES}-byte single-record limit`,
		);
	}
};

const concat = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> => {
	const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
};

/**
 * Validate the payload size and the subscription's public key and auth secret,
 * returning the decoded key bytes. Exported so the send path can reject invalid
 * input *before* paying for the ECDSA VAPID signature (see `send.ts`). The
 * encryption core re-checks as a self-contained guard for direct callers.
 *
 * @throws {Error} if the payload exceeds the single-record limit, or either
 * subscription key is malformed.
 */
export const validatePushInputs = (
	payload: Uint8Array,
	p256dhKey: string,
	authSecret: string,
): { clientPublicKeyBytes: Uint8Array<ArrayBuffer>; authSecretBytes: Uint8Array<ArrayBuffer> } => {
	assertPayloadWithinLimit(payload);

	const clientPublicKeyBytes = urlBase64ToUint8Array(p256dhKey);
	if (
		clientPublicKeyBytes.length !== KEY_ID_LENGTH ||
		clientPublicKeyBytes[0] !== UNCOMPRESSED_POINT_TAG
	) {
		throw new Error(
			"Invalid subscription p256dh key: expected a 65-byte uncompressed P-256 public key",
		);
	}

	const authSecretBytes = urlBase64ToUint8Array(authSecret);
	if (authSecretBytes.length < 16) {
		throw new Error("Invalid subscription auth secret: expected at least 16 bytes");
	}

	return { clientPublicKeyBytes, authSecretBytes };
};

const importClientPublicKey = (rawKey: Uint8Array<ArrayBuffer>): Promise<CryptoKey> =>
	crypto.subtle.importKey("raw", rawKey, { name: "ECDH", namedCurve: "P-256" }, false, []);

const deriveSharedSecret = async (
	serverPrivateKey: CryptoKey,
	clientPublicKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> =>
	new Uint8Array(
		await crypto.subtle.deriveBits(
			{ name: "ECDH", public: clientPublicKey },
			serverPrivateKey,
			256,
		),
	);

const exportRawPublicKey = async (key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> =>
	new Uint8Array(await crypto.subtle.exportKey("raw", key));

const importHkdfKey = (bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> =>
	crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits", "deriveKey"]);

/** `label || 0x00 || context`, the HKDF info construction of RFC 8291 §3.4. */
const hkdfInfo = (label: string, ...context: Uint8Array[]): Uint8Array<ArrayBuffer> =>
	concat(encoder.encode(label), new Uint8Array([0x00]), ...context);

/** PRK = HKDF(salt = auth_secret, IKM = ECDH shared secret) — RFC 8291 §3.4. */
const deriveInputKeyingMaterial = async (
	sharedSecret: Uint8Array<ArrayBuffer>,
	authSecret: Uint8Array<ArrayBuffer>,
	clientPublicKey: Uint8Array,
	serverPublicKey: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> =>
	new Uint8Array(
		await crypto.subtle.deriveBits(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: authSecret,
				info: hkdfInfo("WebPush: info", clientPublicKey, serverPublicKey),
			},
			await importHkdfKey(sharedSecret),
			256,
		),
	);

const deriveContentEncryptionKey = (
	ikmKey: CryptoKey,
	salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> =>
	crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt,
			info: hkdfInfo("Content-Encoding: aes128gcm"),
		},
		ikmKey,
		{ name: "AES-GCM", length: 128 },
		false,
		["encrypt"],
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

const padPayload = (payload: Uint8Array): Uint8Array<ArrayBuffer> =>
	concat(payload, new Uint8Array([PADDING_DELIMITER]));

/** `salt | rs | idlen | keyid`, where keyid is the server's ephemeral public key. */
const contentCodingHeader = (
	salt: Uint8Array<ArrayBuffer>,
	keyId: Uint8Array,
): Uint8Array<ArrayBuffer> => {
	const header = new Uint8Array(HEADER_LENGTH);
	header.set(salt, 0);
	new DataView(header.buffer).setUint32(SALT_LENGTH, RECORD_SIZE, false);
	header[SALT_LENGTH + RECORD_SIZE_LENGTH] = KEY_ID_LENGTH;
	header.set(keyId, SALT_LENGTH + RECORD_SIZE_LENGTH + ID_LENGTH_LENGTH);
	return header;
};

/**
 * Encrypt a payload as a single aes128gcm record (RFC 8291 / RFC 8188),
 * generating a fresh ephemeral key pair and salt for this message.
 *
 * @throws {Error} if the payload is too large or the subscription keys are
 * malformed (see {@link validatePushInputs}).
 */
export const encryptPayload = async (
	payload: Uint8Array,
	p256dhKey: string,
	authSecret: string,
): Promise<Uint8Array<ArrayBuffer>> => {
	const serverKeyPair = await crypto.subtle.generateKey(
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		["deriveBits"],
	);
	const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
	return encryptRecord(payload, p256dhKey, authSecret, serverKeyPair, salt);
};

/**
 * Deterministic core of {@link encryptPayload}: the caller supplies the
 * ephemeral server key pair and salt (normally random, one per message).
 *
 * @internal Not part of the public API — exposed only so the RFC 8291
 * Appendix A known-answer test can pin the output. Never call this in
 * production: a fresh key pair and salt per message is what keeps the scheme
 * safe.
 */
export const encryptRecord = async (
	payload: Uint8Array,
	p256dhKey: string,
	authSecret: string,
	serverKeyPair: CryptoKeyPair,
	salt: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	const { clientPublicKeyBytes, authSecretBytes } = validatePushInputs(
		payload,
		p256dhKey,
		authSecret,
	);

	const clientPublicKey = await importClientPublicKey(clientPublicKeyBytes);
	const sharedSecret = await deriveSharedSecret(serverKeyPair.privateKey, clientPublicKey);
	const serverPublicKey = await exportRawPublicKey(serverKeyPair.publicKey);

	const ikm = await deriveInputKeyingMaterial(
		sharedSecret,
		authSecretBytes,
		clientPublicKeyBytes,
		serverPublicKey,
	);
	const ikmKey = await importHkdfKey(ikm);
	const contentEncryptionKey = await deriveContentEncryptionKey(ikmKey, salt);
	const nonce = await deriveNonce(ikmKey, salt);

	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: nonce },
		contentEncryptionKey,
		padPayload(payload),
	);

	return concat(contentCodingHeader(salt, serverPublicKey), new Uint8Array(ciphertext));
};
