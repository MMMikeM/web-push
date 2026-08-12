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
 * Options for sending one notification to many subscriptions: everything in
 * {@link SendPushOptions}, plus the concurrency bound.
 */
export type SendPushBatchOptions = SendPushOptions & {
	/** Maximum sends in flight at once (default: 100) */
	concurrency?: number;
};

/**
 * The outcome of a batch send, sorted by what to do next: log `delivered`,
 * delete `gone` from your store, inspect `failed`.
 */
export type SendPushBatchResult = {
	/** How many sends the push service accepted */
	delivered: number;
	/** Endpoints the push service reported gone (404/410) — delete these */
	gone: string[];
	/**
	 * Sends that did not deliver, each with its error: a `WebPushError` for a
	 * push-service rejection (carrying `statusCode` and `retryAfter`), a
	 * `TypeError` when `fetch` never reached the service, any other `Error`
	 * for a malformed subscription.
	 */
	failed: { endpoint: string; error: unknown }[];
};

/**
 * Options for sending a push notification.
 */
export type SendPushOptions = {
	/** Optional logger for debugging */
	logger?: Logger;
	/** TTL in seconds (default: 86400 = 24 hours) */
	ttl?: number;
	/**
	 * VAPID JWT expiration in seconds from now (default: 43200 = 12 hours).
	 * Must stay within 24h — push services reject longer-lived tokens (401).
	 * Kept separate from `ttl`, which controls only message retention.
	 */
	vapidExpiration?: number;
	/** Delivery priority (RFC 8030 §5.3). Omit to let the push service decide. */
	urgency?: "very-low" | "low" | "normal" | "high";
	/**
	 * Collapse key (RFC 8030 §5.4): a later push with the same topic replaces
	 * this one while it is still undelivered. Max 32 URL-safe base64 characters.
	 */
	topic?: string;
};
