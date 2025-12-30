/**
 * VAPID (Voluntary Application Server Identification) utilities for Web Push.
 *
 * Uses Web Crypto API for ECDSA P-256 key generation and JWT signing,
 * compatible with Node.js, Cloudflare Workers, and modern browsers.
 */

/**
 * Convert a URL-safe base64 string to a Uint8Array.
 */
export const urlBase64ToUint8Array = (base64String: string): Uint8Array<ArrayBuffer> => {
	if (!base64String) {
		return new Uint8Array(0);
	}

	// Add padding if needed
	const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
	const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");

	const rawData = atob(base64);
	const outputArray = new Uint8Array(rawData.length);

	for (let i = 0; i < rawData.length; ++i) {
		outputArray[i] = rawData.charCodeAt(i);
	}

	return outputArray as Uint8Array<ArrayBuffer>;
};

/**
 * Convert a Uint8Array to a URL-safe base64 string (no padding).
 */
export const uint8ArrayToUrlBase64 = (array: Uint8Array): string => {
	const base64 = btoa(String.fromCharCode(...array));
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/**
 * Generate a new VAPID key pair using ECDSA P-256.
 * Returns keys as URL-safe base64 strings.
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

	// Export public key as raw (uncompressed point)
	const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
	const publicKeyArray = new Uint8Array(publicKeyRaw);

	// Export private key as JWK to get the 'd' value (scalar)
	const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
	const privateKeyArray = urlBase64ToUint8Array(privateKeyJwk.d!);

	return {
		publicKey: uint8ArrayToUrlBase64(publicKeyArray),
		privateKey: uint8ArrayToUrlBase64(privateKeyArray),
	};
};

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

/**
 * Create a VAPID JWT for authenticating with push services.
 */
export const createVapidJwt = async (options: VapidJwtOptions): Promise<string> => {
	const { audience, subject, publicKey, privateKey, expiration = 43200 } = options;

	// JWT Header
	const header = {
		typ: "JWT",
		alg: "ES256",
	};

	// JWT Payload
	const now = Math.floor(Date.now() / 1000);
	const payload = {
		aud: audience,
		exp: now + expiration,
		sub: subject,
	};

	// Encode header and payload
	const encodedHeader = uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(header)));
	const encodedPayload = uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(payload)));

	const unsignedToken = `${encodedHeader}.${encodedPayload}`;

	// Import private key for signing
	const privateKeyArray = urlBase64ToUint8Array(privateKey);
	const publicKeyArray = urlBase64ToUint8Array(publicKey);

	// Create JWK from the raw key components
	const jwk: JsonWebKey = {
		kty: "EC",
		crv: "P-256",
		x: uint8ArrayToUrlBase64(publicKeyArray.slice(1, 33)), // Skip 0x04 prefix, first 32 bytes
		y: uint8ArrayToUrlBase64(publicKeyArray.slice(33)), // Last 32 bytes
		d: uint8ArrayToUrlBase64(privateKeyArray),
	};

	const cryptoKey = await crypto.subtle.importKey(
		"jwk",
		jwk,
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		false,
		["sign"],
	);

	// Sign the token
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		cryptoKey,
		new TextEncoder().encode(unsignedToken),
	);

	const signatureArray = new Uint8Array(signature);
	const encodedSignature = uint8ArrayToUrlBase64(signatureArray);

	return `${unsignedToken}.${encodedSignature}`;
};
