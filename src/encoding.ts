/**
 * Not a package entry point: `./vapid` re-exports the base64url codec, and the
 * key decoders stay internal.
 */

const P256_PUBLIC_KEY_LENGTH = 65;
const UNCOMPRESSED_POINT_TAG = 0x04;

/**
 * Convert a URL-safe base64 string to a Uint8Array.
 *
 * @throws {DOMException} `InvalidCharacterError` if the input is not base64url.
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

const decodeOrUndefined = (base64: string): Uint8Array<ArrayBuffer> | undefined => {
	try {
		return urlBase64ToUint8Array(base64);
	} catch {
		return undefined;
	}
};

/**
 * Decode a URL-safe base64 uncompressed P-256 public key: 65 bytes, `0x04` first.
 *
 * @param errorMessage Thrown for anything else, including input that is not base64url.
 * @throws {Error} with `errorMessage` if the input does not decode to such a key.
 */
export const decodeP256PublicKey = (
	base64: string,
	errorMessage: string,
): Uint8Array<ArrayBuffer> => {
	const key = decodeOrUndefined(base64);
	if (key?.length !== P256_PUBLIC_KEY_LENGTH || key[0] !== UNCOMPRESSED_POINT_TAG) {
		throw new Error(errorMessage);
	}
	return key;
};

/**
 * Decode an application server's VAPID public key.
 *
 * @throws {Error} if it is not a base64url 65-byte uncompressed P-256 point.
 */
export const decodeVapidPublicKey = (publicKey: string): Uint8Array<ArrayBuffer> =>
	decodeP256PublicKey(publicKey, "VAPID public key must be a 65-byte uncompressed P-256 point");
