/**
 * Web Push notification sending module.
 *
 * Implements the Web Push protocol with VAPID authentication and
 * aes128gcm content encryption (RFC 8291) using Web Crypto API.
 */

import type { PushPayload, PushSubscriptionData, SendPushOptions, VapidConfig } from "./types";
import { createVapidJwt, urlBase64ToUint8Array } from "./vapid";

export type { PushSubscriptionData, PushPayload, VapidConfig, SendPushOptions };

/**
 * Send a push notification to a subscription endpoint.
 *
 * @param subscription - The push subscription to send to
 * @param payload - The notification payload
 * @param vapid - VAPID configuration
 * @param options - Optional settings (logger, TTL)
 * @returns true if successful, false if subscription is invalid (should be deleted)
 * @throws Error on server errors or rate limits
 */
export const sendPushNotification = async (
	subscription: PushSubscriptionData,
	payload: PushPayload,
	vapid: VapidConfig,
	options: SendPushOptions = {},
): Promise<boolean> => {
	const { logger, ttl = 86400 } = options;

	const url = new URL(subscription.endpoint);
	const audience = `${url.protocol}//${url.host}`;

	// Create VAPID JWT
	const jwt = await createVapidJwt({
		audience,
		subject: vapid.subject,
		publicKey: vapid.publicKey,
		privateKey: vapid.privateKey,
		expiration: ttl,
	});

	// Encrypt the payload
	const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
	const encryptedPayload = await encryptPayload(
		payloadBytes,
		subscription.keys.p256dh,
		subscription.keys.auth,
	);

	// Send the push request
	const response = await fetch(subscription.endpoint, {
		method: "POST",
		headers: {
			Authorization: `vapid t=${jwt}, k=${vapid.publicKey}`,
			"Content-Encoding": "aes128gcm",
			"Content-Type": "application/octet-stream",
			TTL: String(ttl),
		},
		body: encryptedPayload,
	});

	const responseText = await response.text();

	logger?.debug?.("Push response", {
		endpoint: subscription.endpoint.slice(0, 50),
		status: response.status,
		statusText: response.statusText,
		body: responseText.slice(0, 200),
	});

	if (response.ok) {
		return true;
	}

	// 404 or 410 means the subscription is no longer valid
	if (response.status === 404 || response.status === 410) {
		return false;
	}

	// 429 rate limit
	if (response.status === 429) {
		throw new Error(`Push rate limit exceeded: ${response.statusText}`);
	}

	// Other errors
	throw new Error(`Push service error: ${response.status} ${response.statusText}`);
};

/**
 * Encrypt payload using Web Push encryption (aes128gcm).
 *
 * Implementation follows RFC 8291 (Message Encryption for Web Push).
 */
const encryptPayload = async (
	payload: Uint8Array,
	p256dhKey: string,
	authSecret: string,
): Promise<Uint8Array<ArrayBuffer>> => {
	// Generate ephemeral ECDH key pair
	const localKeyPair = await crypto.subtle.generateKey(
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		["deriveBits"],
	);

	// Import client's public key
	const clientPublicKeyBytes = urlBase64ToUint8Array(p256dhKey);
	const clientPublicKey = await crypto.subtle.importKey(
		"raw",
		clientPublicKeyBytes as Uint8Array<ArrayBuffer>,
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		[],
	);

	// Derive shared secret via ECDH
	const sharedSecretBits = await crypto.subtle.deriveBits(
		{ name: "ECDH", public: clientPublicKey },
		localKeyPair.privateKey,
		256,
	);
	const sharedSecret = new Uint8Array(sharedSecretBits);

	// Export local public key
	const localPublicKeyRaw = await crypto.subtle.exportKey("raw", localKeyPair.publicKey);
	const localPublicKey = new Uint8Array(localPublicKeyRaw);

	// Auth secret
	const authSecretBytes = urlBase64ToUint8Array(authSecret);

	// Generate salt
	const salt = crypto.getRandomValues(new Uint8Array(16));

	// Derive encryption key and nonce using HKDF
	const { contentEncryptionKey, nonce } = await deriveKeyAndNonce(
		sharedSecret,
		authSecretBytes,
		clientPublicKeyBytes,
		localPublicKey,
		salt,
	);

	// Pad the payload (add padding delimiter)
	const paddedPayload = new Uint8Array(payload.length + 1);
	paddedPayload.set(payload);
	paddedPayload[payload.length] = 0x02; // Padding delimiter

	// Encrypt with AES-128-GCM
	const encrypted = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: nonce as Uint8Array<ArrayBuffer> },
		contentEncryptionKey,
		paddedPayload,
	);

	// Build the aes128gcm content encoding header
	// Format: salt (16) + rs (4) + idlen (1) + keyid (65) + encrypted data
	const recordSize = 4096;
	const header = new Uint8Array(16 + 4 + 1 + 65);
	header.set(salt, 0); // Salt
	new DataView(header.buffer).setUint32(16, recordSize, false); // Record size (big endian)
	header[20] = 65; // Key ID length
	header.set(localPublicKey, 21); // Key ID (local public key)

	// Combine header and encrypted data
	const result = new Uint8Array(header.length + encrypted.byteLength);
	result.set(header);
	result.set(new Uint8Array(encrypted), header.length);

	return result;
};

/**
 * Derive content encryption key and nonce using HKDF.
 */
const deriveKeyAndNonce = async (
	sharedSecret: Uint8Array,
	authSecret: Uint8Array,
	clientPublicKey: Uint8Array,
	localPublicKey: Uint8Array,
	salt: Uint8Array,
): Promise<{ contentEncryptionKey: CryptoKey; nonce: Uint8Array }> => {
	const encoder = new TextEncoder();

	// Build info for IKM
	// "WebPush: info" || 0x00 || client_public_key || server_public_key
	const ikmInfo = new Uint8Array([
		...encoder.encode("WebPush: info"),
		0x00,
		...clientPublicKey,
		...localPublicKey,
	]);

	// Derive IKM from shared secret using auth secret
	// RFC 8291: PRK = HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
	const sharedSecretKey = await crypto.subtle.importKey(
		"raw",
		sharedSecret as Uint8Array<ArrayBuffer>,
		"HKDF",
		false,
		["deriveBits"],
	);

	const ikmBits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: authSecret as Uint8Array<ArrayBuffer>,
			info: ikmInfo as Uint8Array<ArrayBuffer>,
		},
		sharedSecretKey,
		256,
	);
	const ikm = new Uint8Array(ikmBits);

	// Import IKM for HKDF
	const ikmKey = await crypto.subtle.importKey(
		"raw",
		ikm as Uint8Array<ArrayBuffer>,
		"HKDF",
		false,
		["deriveBits", "deriveKey"],
	);

	// Derive content encryption key (CEK)
	// info: "Content-Encoding: aes128gcm" || 0x00
	const cekInfo = new Uint8Array([...encoder.encode("Content-Encoding: aes128gcm"), 0x00]);
	const contentEncryptionKey = await crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: salt as Uint8Array<ArrayBuffer>,
			info: cekInfo as Uint8Array<ArrayBuffer>,
		},
		ikmKey,
		{ name: "AES-GCM", length: 128 },
		false,
		["encrypt"],
	);

	// Derive nonce
	// info: "Content-Encoding: nonce" || 0x00
	const nonceInfo = new Uint8Array([...encoder.encode("Content-Encoding: nonce"), 0x00]);
	const nonceBits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: salt as Uint8Array<ArrayBuffer>,
			info: nonceInfo as Uint8Array<ArrayBuffer>,
		},
		ikmKey,
		96, // 12 bytes
	);
	const nonce = new Uint8Array(nonceBits);

	return { contentEncryptionKey, nonce };
};
