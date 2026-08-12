/**
 * VAPID — Voluntary Application Server Identification (RFC 8292). The ECDSA
 * P-256 key pair and signed JWT that identify an application server to a push
 * service, so it will accept pushes for its subscriptions.
 */

/**
 * Convert a URL-safe base64 string to a Uint8Array.
 */
export const urlBase64ToUint8Array = (base64String: string): Uint8Array<ArrayBuffer> => {
	if (!base64String) {
		return new Uint8Array(0);
	}

	const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
	const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");

	const rawData = atob(base64);
	const outputArray = new Uint8Array(rawData.length);

	for (let i = 0; i < rawData.length; ++i) {
		outputArray[i] = rawData.charCodeAt(i);
	}

	return outputArray;
};

/**
 * Convert a Uint8Array to a URL-safe base64 string (no padding).
 */
export const uint8ArrayToUrlBase64 = (array: Uint8Array): string => {
	// Build the binary string in chunks — String.fromCharCode(...array) spreads
	// every byte as a call argument and overflows the stack for large inputs.
	let binary = "";
	const chunkSize = 0x8000;
	for (let i = 0; i < array.length; i += chunkSize) {
		binary += String.fromCharCode(...array.subarray(i, i + chunkSize));
	}
	const base64 = btoa(binary);
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/**
 * Generate a new VAPID key pair using ECDSA P-256.
 * Returns keys as URL-safe base64 strings.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = await generateVapidKeys();
 * console.log({ publicKey, privateKey });
 * ```
 */
export const generateVapidKeys = async (): Promise<{
	publicKey: string;
	privateKey: string;
}> => {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		true,
		["sign", "verify"],
	);

	const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
	// Private keys have no "raw" export; `d` is the P-256 scalar within the JWK.
	const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
	if (!privateKeyJwk.d) {
		throw new Error("Generated P-256 key exported without a private scalar");
	}

	return {
		publicKey: uint8ArrayToUrlBase64(new Uint8Array(publicKeyRaw)),
		privateKey: uint8ArrayToUrlBase64(urlBase64ToUint8Array(privateKeyJwk.d)),
	};
};

/** Inputs for {@link createVapidJwt}. */
export type VapidJwtOptions = {
	/** The origin of the push service (e.g., https://fcm.googleapis.com) */
	audience: string;
	/** Contact information for the application server (e.g., mailto:admin@example.com) */
	subject: string;
	/** VAPID public key as URL-safe base64 */
	publicKey: string;
	/** VAPID private key as URL-safe base64 */
	privateKey: string;
	/** Token expiration in seconds from now (default: 12 hours) */
	expiration?: number;
};

const encodeJwtSegment = (segment: object): string =>
	uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(segment)));

/**
 * Rebuild the ECDSA signing key from the raw VAPID key pair. Web Crypto has no
 * "raw" import for private keys, so the P-256 point is split into the JWK
 * coordinates it does accept.
 *
 * @throws {Error} if either key is the wrong length or encoding.
 */
const importSigningKey = (publicKey: string, privateKey: string): Promise<CryptoKey> => {
	const publicKeyArray = urlBase64ToUint8Array(publicKey);
	const privateKeyArray = urlBase64ToUint8Array(privateKey);
	if (publicKeyArray.length !== 65 || publicKeyArray[0] !== 0x04) {
		throw new Error("VAPID public key must be a 65-byte uncompressed P-256 point");
	}
	if (privateKeyArray.length !== 32) {
		throw new Error("VAPID private key must be a 32-byte P-256 scalar");
	}

	const jwk: JsonWebKey = {
		kty: "EC",
		crv: "P-256",
		x: uint8ArrayToUrlBase64(publicKeyArray.slice(1, 33)),
		y: uint8ArrayToUrlBase64(publicKeyArray.slice(33)),
		d: uint8ArrayToUrlBase64(privateKeyArray),
	};
	return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
		"sign",
	]);
};

/**
 * Create a VAPID JWT for authenticating with push services.
 *
 * @throws {Error} if the expiration is outside 1–86400 seconds, the subject is
 * not a `mailto:`/`https://` URI, or either key is malformed.
 */
export const createVapidJwt = async (options: VapidJwtOptions): Promise<string> => {
	const { audience, subject, publicKey, privateKey, expiration = 43200 } = options;

	// VAPID JWT lifetime is capped at 24h (RFC 8292 §2); services reject longer.
	if (expiration <= 0 || expiration > 86400) {
		throw new Error("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");
	}
	// RFC 8292 §2.1: the subject must be a contact URI (mailto: or https:).
	if (!/^(mailto:|https:\/\/)/.test(subject)) {
		throw new Error("VAPID subject must be a 'mailto:' or 'https://' URI");
	}

	const now = Math.floor(Date.now() / 1000);
	const unsignedToken = [
		{ typ: "JWT", alg: "ES256" },
		{ aud: audience, exp: now + expiration, sub: subject },
	]
		.map(encodeJwtSegment)
		.join(".");

	const signingKey = await importSigningKey(publicKey, privateKey);
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		signingKey,
		new TextEncoder().encode(unsignedToken),
	);

	return `${unsignedToken}.${uint8ArrayToUrlBase64(new Uint8Array(signature))}`;
};
