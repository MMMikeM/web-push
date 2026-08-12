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
import { createVapidJwt } from "./vapid";

export type {
	PushSubscriptionData,
	PushPayload,
	VapidConfig,
	SendPushOptions,
	SendPushBatchOptions,
	SendPushBatchResult,
};

/**
 * Error thrown when the push service rejects a send with a non-2xx status,
 * other than 404/410 ("gone"), which resolve to `false` instead. Carries the
 * status, response body, endpoint, and any `Retry-After` header for backoff.
 */
export class WebPushError extends Error {
	readonly statusCode: number;
	readonly body: string;
	readonly endpoint: string;
	readonly retryAfter: string | null;

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
	}
}

/** RFC 8030 §5.4: a collapse key of at most 32 URL-safe base64 characters. */
const assertValidTopic = (topic: string | undefined): void => {
	if (topic !== undefined && !/^[A-Za-z0-9\-_]{1,32}$/.test(topic)) {
		throw new Error("Topic must be 1-32 URL-safe base64 characters");
	}
};

/** The JWT `aud` claim is the push service origin, not the full endpoint. */
const pushServiceOrigin = (endpoint: string): string => {
	const url = new URL(endpoint);
	return `${url.protocol}//${url.host}`;
};

/** 404 Not Found and 410 Gone both mean the subscription should be deleted. */
const isSubscriptionGone = (status: number): boolean => status === 404 || status === 410;

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
	const { logger, ttl = 86400, urgency, topic } = options;

	const encryptedPayload = await encryptPayload(
		payloadBytes,
		subscription.keys.p256dh,
		subscription.keys.auth,
	);

	const response = await fetch(subscription.endpoint, {
		method: "POST",
		headers: buildPushHeaders({ jwt, vapidPublicKey, ttl, urgency, topic }),
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
 * @returns true if successful, false if subscription is invalid (should be deleted)
 * @throws {WebPushError} on rate limits (429) and other push service errors
 * @throws {Error} on invalid input: VAPID config, payload size, `topic`
 */
export const sendPushNotification = async (
	subscription: PushSubscriptionData,
	payload: PushPayload,
	vapid: VapidConfig,
	options: SendPushOptions = {},
): Promise<boolean> => {
	assertValidTopic(options.topic);

	// Reject bad input *before* signing the VAPID JWT — no point paying for an
	// ECDSA signature on a request we'll refuse.
	const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
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
 * for the whole batch.
 *
 * @throws {Error} on caller input — invalid VAPID config, oversized payload,
 * invalid `topic` or `concurrency` — before anything is sent.
 * @example
 * ```ts
 * const { delivered, gone, failed } = await sendPushBatch(subscriptions, payload, vapid);
 * await removeFromStore(gone);
 * for (const { endpoint, error } of failed) console.warn("push failed", endpoint, error);
 * ```
 */
export const sendPushBatch = async (
	subscriptions: readonly PushSubscriptionData[],
	payload: PushPayload,
	vapid: VapidConfig,
	options: SendPushBatchOptions = {},
): Promise<SendPushBatchResult> => {
	const { concurrency = 100, ...sendOptions } = options;
	if (!Number.isInteger(concurrency) || concurrency < 1) {
		throw new Error("concurrency must be a positive integer");
	}
	assertValidTopic(sendOptions.topic);

	const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
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
			// oxlint-disable-next-line no-await-in-loop -- one worker is one lane of the pool; awaiting here is the concurrency bound
			await sendOne(subscription);
		}
	};

	await Promise.all(Array.from({ length: Math.min(concurrency, subscriptions.length) }, worker));
	return { delivered, gone, failed };
};
