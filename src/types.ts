/**
 * Shared types for Web Push library.
 */

/**
 * A push subscription from the browser's PushManager.
 */
export type PushSubscriptionData = {
	/** The push service endpoint URL */
	endpoint: string;
	/** Encryption keys from the subscription */
	keys: {
		/** Client's ECDH public key (P-256, URL-safe base64) */
		p256dh: string;
		/** Client's auth secret (URL-safe base64) */
		auth: string;
	};
};

/**
 * Payload to send in a push notification.
 */
export type PushPayload = {
	/** Notification title */
	title: string;
	/** Notification body text */
	body: string;
	/** URL to open when notification is clicked */
	url?: string;
	/** Tag for notification grouping/replacement */
	tag?: string;
};

/**
 * VAPID configuration for sending push notifications.
 */
export type VapidConfig = {
	/** VAPID public key (URL-safe base64) */
	publicKey: string;
	/** VAPID private key (URL-safe base64) */
	privateKey: string;
	/** Contact URI (e.g., mailto:admin@example.com) */
	subject: string;
};

/**
 * Optional logger interface for debugging.
 */
export type Logger = {
	debug?: (message: string, data?: Record<string, unknown>) => void;
	info?: (message: string, data?: Record<string, unknown>) => void;
	warn?: (message: string, data?: Record<string, unknown>) => void;
	error?: (message: string, data?: Record<string, unknown>) => void;
};

/**
 * Options for sending a push notification.
 */
export type SendPushOptions = {
	/** Optional logger for debugging */
	logger?: Logger;
	/** TTL in seconds (default: 86400 = 24 hours) */
	ttl?: number;
};
