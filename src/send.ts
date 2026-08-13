/**
 * The HTTP half of a push: VAPID auth (RFC 8292) over an aes128gcm-encrypted
 * body (RFC 8291), plus the status handling that decides delivered / gone / error.
 */

import { assertPayloadWithinLimit, encryptPayload, validatePushInputs } from "./encrypt";
import type {
	PushPayload,
	PushSubscriptionData,
	SendPushBatchOptions,
	SendPushBatchResult,
	SendPushOptions,
	VapidConfig,
} from "./types";
import { createVapidJwt, uint8ArrayToUrlBase64 } from "./vapid";

export type {
	PushSubscriptionData,
	PushPayload,
	VapidConfig,
	SendPushOptions,
	SendPushBatchOptions,
	SendPushBatchResult,
};

/** RFC 9110 §10.2.3: `Retry-After` is either delta-seconds or an HTTP-date. */
const parseRetryAfterMs = (retryAfter: string | null): number | null => {
	if (retryAfter === null) {
		return null;
	}
	const trimmed = retryAfter.trim();
	if (/^\d+$/.test(trimmed)) {
		return Number(trimmed) * 1000;
	}
	const date = Date.parse(trimmed);
	return Number.isNaN(date) ? null : Math.max(0, date - Date.now());
};

/**
 * Error thrown when the push service rejects a send with a non-2xx status,
 * other than 404/410 ("gone"), which resolve to `false` instead. Carries the
 * status, response body, endpoint, and the `Retry-After` header both verbatim
 * (`retryAfter`) and parsed to milliseconds-from-now (`retryAfterMs`).
 */
export class WebPushError extends Error {
	readonly statusCode: number;
	readonly body: string;
	/**
	 * The full subscription endpoint, a capability URL: anyone holding it can
	 * push to the device. Route on it, but keep it out of logs; serializers
	 * that honor `toJSON` get a truncated one.
	 */
	readonly endpoint: string;
	/** The `Retry-After` header verbatim: delta-seconds or an HTTP-date */
	readonly retryAfter: string | null;
	/** `Retry-After` as milliseconds from now; `null` when absent or unparseable */
	readonly retryAfterMs: number | null;

	constructor(
		message: string,
		statusCode: number,
		body: string,
		endpoint: string,
		retryAfter: string | null = null,
	) {
		super(message);
		this.name = "WebPushError";
		this.statusCode = statusCode;
		this.body = body;
		this.endpoint = endpoint;
		this.retryAfter = retryAfter;
		this.retryAfterMs = parseRetryAfterMs(retryAfter);
	}

	/**
	 * Truncates `endpoint` and `body` for serialization. Without this,
	 * `JSON.stringify` on the error would emit every enumerable field,
	 * persisting the full capability URL into any structured log.
	 */
	toJSON(): Record<string, string | number | null> {
		return {
			name: this.name,
			message: this.message,
			statusCode: this.statusCode,
			endpoint: this.endpoint.slice(0, 50),
			body: this.body.slice(0, 200),
			retryAfter: this.retryAfter,
			retryAfterMs: this.retryAfterMs,
		};
	}
}

// The private field makes the type nominal: nothing structural can forge
// `#bytes`, so the only way to send raw bytes is through `rawPayload(...)`,
// keeping every opt-out of the typed contract greppable at the call site.
class RawBytes {
	readonly #bytes: Uint8Array;

	constructor(bytes: Uint8Array) {
		this.#bytes = bytes;
	}

	get bytes(): Uint8Array {
		return this.#bytes;
	}
}

/**
 * A payload the caller has already serialized, accepted by
 * {@link sendPushNotification} and {@link sendPushBatch} in place of a
 * `PushPayload`. Created by {@link rawPayload}.
 */
export type RawPushPayload = RawBytes;

/**
 * Mark a payload as already serialized: the string or bytes are encrypted and
 * delivered verbatim, so your service worker's parsing is the other half of
 * the contract. The README service worker expects `PushPayload` JSON and will
 * throw on anything else — which is also why the send functions take this
 * wrapper rather than a bare string: a misdirected string would type-check,
 * deliver, and only fail inside `event.data.json()` on the device.
 */
export const rawPayload = (payload: string | Uint8Array): RawPushPayload =>
	new RawBytes(typeof payload === "string" ? new TextEncoder().encode(payload) : payload);

const encodePayload = (payload: PushPayload | RawPushPayload): Uint8Array =>
	payload instanceof RawBytes ? payload.bytes : new TextEncoder().encode(JSON.stringify(payload));

/**
 * Derive a valid `topic` from an arbitrary string, for collapse keys that
 * don't fit the RFC 8030 §5.4 charset or length (`message:${id}`, a URL, …).
 * Deterministic — the same input always yields the same topic, which is what
 * makes push-service collapse work — and opaque, so the key's content never
 * appears in a header the push service can read (only the payload is
 * encrypted; headers are plaintext to the service). The first 32 base64url
 * characters of a SHA-256 digest carry 192 bits, leaving collisions
 * negligible.
 *
 * Strings that are already valid topics are hashed too, never passed through:
 * a conditional pass-through would make near-identical inputs produce
 * unrelated wire values. Set {@link SendPushOptions.topic} directly when you
 * need an exact header value.
 */
export const topicFromString = async (input: string): Promise<string> => {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return uint8ArrayToUrlBase64(new Uint8Array(digest)).slice(0, 32);
};

/** RFC 8030 §5.4: a collapse key of at most 32 URL-safe base64 characters. */
const assertValidTopic = (topic: string | undefined): void => {
	if (topic !== undefined && !/^[A-Za-z0-9\-_]{1,32}$/.test(topic)) {
		throw new Error("Topic must be 1-32 URL-safe base64 characters");
	}
};

/** The JWT `aud` claim is the push service origin, not the full endpoint. */
const pushServiceOrigin = (endpoint: string): string => {
	const url = new URL(endpoint);
	// Anything but TLS hands the capability URL and payload to the network.
	if (url.protocol !== "https:") {
		throw new Error("Invalid subscription endpoint: must be an https: URL (RFC 8030 §3)");
	}
	return `${url.protocol}//${url.host}`;
};

/** 404 Not Found and 410 Gone both mean the subscription should be deleted. */
const isSubscriptionGone = (status: number): boolean => status === 404 || status === 410;

const DEFAULT_TIMEOUT_MS = 30000;

const assertValidTimeout = (timeoutMs: number): void => {
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
		throw new Error("timeoutMs must be a positive number of milliseconds");
	}
};

const requestSignal = (signal: AbortSignal | undefined, timeoutMs: number): AbortSignal =>
	signal
		? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
		: AbortSignal.timeout(timeoutMs);

const buildPushHeaders = ({
	jwt,
	vapidPublicKey,
	ttl,
	urgency,
	topic,
}: {
	jwt: string;
	vapidPublicKey: string;
	ttl: number;
	urgency: SendPushOptions["urgency"];
	topic: string | undefined;
}): Record<string, string> => {
	const headers: Record<string, string> = {
		Authorization: `vapid t=${jwt}, k=${vapidPublicKey}`,
		"Content-Encoding": "aes128gcm",
		"Content-Type": "application/octet-stream",
		TTL: String(ttl),
	};
	if (urgency) headers.Urgency = urgency;
	if (topic) headers.Topic = topic;
	return headers;
};

const postToPushService = async (
	subscription: PushSubscriptionData,
	payloadBytes: Uint8Array,
	jwt: string,
	vapidPublicKey: string,
	options: SendPushOptions,
): Promise<boolean> => {
	const { logger, ttl = 86400, urgency, topic, signal, timeoutMs = DEFAULT_TIMEOUT_MS } = options;

	const encryptedPayload = await encryptPayload(
		payloadBytes,
		subscription.keys.p256dh,
		subscription.keys.auth,
	);

	const response = await fetch(subscription.endpoint, {
		method: "POST",
		headers: buildPushHeaders({ jwt, vapidPublicKey, ttl, urgency, topic }),
		body: encryptedPayload,
		signal: requestSignal(signal, timeoutMs),
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

	if (isSubscriptionGone(response.status)) {
		return false;
	}

	throw new WebPushError(
		response.status === 429
			? `Push rate limit exceeded: ${response.statusText}`
			: `Push service error: ${response.status} ${response.statusText}`,
		response.status,
		responseText,
		subscription.endpoint,
		response.headers.get("retry-after"),
	);
};

/**
 * Send a push notification to a subscription endpoint.
 *
 * Each request carries a timeout (default 30s) and, when provided, the
 * caller's `signal`; hitting either rejects with the abort reason.
 *
 * @param payload A `PushPayload` is JSON-serialized; a {@link rawPayload}
 * wrapper is encrypted and sent verbatim
 * @returns true if successful, false if subscription is invalid (should be deleted)
 * @throws {WebPushError} on rate limits (429) and other push service errors
 * @throws {Error} on invalid input: VAPID config, payload size, `topic`,
 * `timeoutMs`, or a non-`https:` endpoint
 * @example
 * ```ts
 * const delivered = await sendPushNotification(subscription, payload, vapid);
 * if (!delivered) await removeFromStore(subscription.endpoint);
 * ```
 */
export const sendPushNotification = async (
	subscription: PushSubscriptionData,
	payload: PushPayload | RawPushPayload,
	vapid: VapidConfig,
	options: SendPushOptions = {},
): Promise<boolean> => {
	assertValidTopic(options.topic);
	assertValidTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

	// Reject bad input *before* signing the VAPID JWT — no point paying for an
	// ECDSA signature on a request we'll refuse.
	const payloadBytes = encodePayload(payload);
	validatePushInputs(payloadBytes, subscription.keys.p256dh, subscription.keys.auth);

	// JWT expiry is independent of the message TTL: push services reject tokens
	// valid for more than 24h, whereas TTL (message retention) is routinely longer.
	const jwt = await createVapidJwt({
		audience: pushServiceOrigin(subscription.endpoint),
		subject: vapid.subject,
		publicKey: vapid.publicKey,
		privateKey: vapid.privateKey,
		expiration: options.vapidExpiration ?? 43200,
	});

	return postToPushService(subscription, payloadBytes, jwt, vapid.publicKey, options);
};

/**
 * Send one notification to every subscription through a bounded worker pool.
 *
 * Per-subscription failures never reject the batch: `delivered` counts the
 * sends the push service accepted, endpoints it reported gone (404/410) come
 * back in `gone` for deletion, and every other failed send comes back in
 * `failed` with its error. One VAPID JWT is signed per push-service origin
 * rather than per message, since the token is scoped to the origin and valid
 * for the whole batch. Aborting `options.signal` stops workers from starting
 * new sends; subscriptions never attempted count toward none of the three.
 *
 * @param payload A `PushPayload` is JSON-serialized; a {@link rawPayload}
 * wrapper is encrypted and sent verbatim
 * @throws {Error} on caller input — invalid VAPID config, oversized payload,
 * invalid `topic`, `concurrency`, or `timeoutMs` — before anything is sent.
 * A non-`https:` endpoint is per-subscription data and lands in `failed`.
 * @example
 * ```ts
 * const { delivered, gone, failed } = await sendPushBatch(subscriptions, payload, vapid);
 * await removeFromStore(gone);
 * for (const { endpoint, error } of failed) console.warn("push failed", endpoint, error);
 * ```
 */
export const sendPushBatch = async (
	subscriptions: readonly PushSubscriptionData[],
	payload: PushPayload | RawPushPayload,
	vapid: VapidConfig,
	options: SendPushBatchOptions = {},
): Promise<SendPushBatchResult> => {
	const { concurrency = 100, ...sendOptions } = options;
	if (!Number.isInteger(concurrency) || concurrency < 1) {
		throw new Error("concurrency must be a positive integer");
	}
	assertValidTopic(sendOptions.topic);
	assertValidTimeout(sendOptions.timeoutMs ?? DEFAULT_TIMEOUT_MS);

	const payloadBytes = encodePayload(payload);
	assertPayloadWithinLimit(payloadBytes);

	const vapidJwtFor = (audience: string): Promise<string> =>
		createVapidJwt({
			audience,
			subject: vapid.subject,
			publicKey: vapid.publicKey,
			privateKey: vapid.privateKey,
			expiration: sendOptions.vapidExpiration ?? 43200,
		});

	// Sign a throwaway token so a bad VAPID config (subject, expiration, key
	// shape) throws once here instead of repeating in `failed` per subscription.
	await vapidJwtFor("https://push.invalid");

	// Caching the promise, not the token, so concurrent workers hitting the
	// same origin share one signature instead of racing to sign their own.
	const jwtByOrigin = new Map<string, Promise<string>>();
	const cachedJwtFor = (origin: string): Promise<string> => {
		const cached = jwtByOrigin.get(origin);
		if (cached) {
			return cached;
		}
		const jwt = vapidJwtFor(origin);
		jwtByOrigin.set(origin, jwt);
		return jwt;
	};

	let delivered = 0;
	const gone: string[] = [];
	const failed: SendPushBatchResult["failed"] = [];

	const sendOne = async (subscription: PushSubscriptionData): Promise<void> => {
		try {
			validatePushInputs(payloadBytes, subscription.keys.p256dh, subscription.keys.auth);
			const jwt = await cachedJwtFor(pushServiceOrigin(subscription.endpoint));
			const accepted = await postToPushService(
				subscription,
				payloadBytes,
				jwt,
				vapid.publicKey,
				sendOptions,
			);
			if (accepted) {
				delivered += 1;
			} else {
				gone.push(subscription.endpoint);
			}
		} catch (error) {
			failed.push({ endpoint: subscription.endpoint, error });
		}
	};

	// One shared iterator: each worker's `for..of` pulls the next unclaimed
	// subscription, so no send waits on the slowest request of a batch.
	const queue = subscriptions.values();
	const worker = async (): Promise<void> => {
		for (const subscription of queue) {
			if (sendOptions.signal?.aborted) {
				return;
			}
			// oxlint-disable-next-line no-await-in-loop -- one worker is one lane of the pool; awaiting here is the concurrency bound
			await sendOne(subscription);
		}
	};

	await Promise.all(Array.from({ length: Math.min(concurrency, subscriptions.length) }, worker));
	return { delivered, gone, failed };
};
