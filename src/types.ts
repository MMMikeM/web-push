/**
 * A push subscription in transit: what {@link serializeSubscription} produces in
 * the browser, and what your server stores and sends to.
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
 * The typed payload form, JSON-serialized for the service worker to read back
 * with `event.data.json()`. For a payload you have already serialized, wrap it
 * in `rawPayload(...)` instead.
 */
export type PushPayload = {
	/** The notification's title, the one required field */
	title: string;
	/** Omit for a title-only notification */
	body?: string;
	/** URL to open when notification is clicked */
	url?: string;
	/** Tag for notification grouping/replacement */
	tag?: string;
};

/**
 * VAPID configuration for sending push notifications.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/runtime-setup/ | Runtime setup}
 * @see {@link https://web-push.thelazyweb.dev/guides/rotate-vapid-keys/ | Rotate VAPID keys}
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
	/** Receives each push service response, endpoint and body truncated */
	debug?: (message: string, data?: Record<string, unknown>) => void;
	/** Not called yet */
	info?: (message: string, data?: Record<string, unknown>) => void;
	/** Not called yet */
	warn?: (message: string, data?: Record<string, unknown>) => void;
	/** Not called yet */
	error?: (message: string, data?: Record<string, unknown>) => void;
};

/**
 * Options for sending one notification to many subscriptions: everything in
 * {@link SendPushOptions}, plus the concurrency bound.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/send-to-many/ | Send to many}
 */
export type SendPushBatchOptions = SendPushOptions & {
	/** Maximum sends in flight at once (default: 100) */
	concurrency?: number;
};

/**
 * The outcome of a batch send, sorted by what to do next: log `delivered`,
 * delete `gone` from your store, inspect `failed`.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/send-to-many/ | Send to many}
 * @see {@link https://web-push.thelazyweb.dev/guides/handle-errors/ | Handle errors and retries}
 */
export type SendPushBatchResult = {
	/** How many sends the push service accepted */
	delivered: number;
	/** Endpoints the push service reported gone (404/410) — delete these */
	gone: string[];
	/**
	 * Sends that did not deliver, each with its error. A plain `Error` means the
	 * subscription itself is malformed: delete it. A row that isn't an object at
	 * all, such as `null`, has an empty `endpoint`, so find it in your own data
	 * rather than deleting by endpoint. A `WebPushError` is a
	 * push-service rejection carrying `statusCode` and `retryAfterMs`; a 401 or
	 * 403 usually means the subscription was made with a different VAPID key. A
	 * `TypeError` (the network) or a `TimeoutError` is worth retrying, and the
	 * `signal`'s abort reason means you cut the send short.
	 */
	failed: { endpoint: string; error: unknown }[];
};

/**
 * Options for sending a push notification.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/collapse-notifications/ | Collapse and expire notifications}
 */
export type SendPushOptions = {
	/** Receives each push service response at `debug` level, endpoint and body truncated */
	logger?: Logger;
	/** TTL in seconds, 0 or more, rounded down to a whole second (default: 86400 = 24 hours) */
	ttl?: number;
	/**
	 * VAPID JWT expiration in seconds from now (default: 43200 = 12 hours). RFC 8292
	 * caps it at 24 hours, so anything but a whole number from 1 to 86400 throws an
	 * `Error` before any request is made, and {@link sendPushBatch} throws it once for
	 * the whole batch.
	 * Kept separate from `ttl`, which controls only message retention.
	 */
	vapidExpiration?: number;
	/**
	 * Delivery priority ({@link https://www.rfc-editor.org/rfc/rfc8030#section-5.3 | RFC 8030 §5.3}).
	 * Omit to let the push service decide.
	 */
	urgency?: "very-low" | "low" | "normal" | "high";
	/**
	 * Collapse key ({@link https://www.rfc-editor.org/rfc/rfc8030#section-5.4 | RFC 8030 §5.4}): a
	 * later push with the same topic replaces this one while it is still undelivered. Max 32
	 * URL-safe base64 characters; derive one from an arbitrary string with {@link topicFromString}.
	 */
	topic?: string;
	/** Aborts in-flight sends; a batch also stops starting new ones. */
	signal?: AbortSignal;
	/**
	 * Per-request timeout in milliseconds, at most 2^31 - 1 and rounded up to a
	 * whole millisecond (default: 30000). Without one, a push service that
	 * accepts the connection and never responds holds its pool slot for as long
	 * as the platform allows.
	 */
	timeoutMs?: number;
};
