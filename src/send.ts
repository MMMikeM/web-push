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
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/handle-errors/ | Handle errors and retries}
 * @see {@link https://web-push.thelazyweb.dev/guides/secure-endpoints/ | Secure your endpoints}
 */
export class WebPushError extends Error {
	/** The push service's HTTP status */
	readonly statusCode: number;
	/** The push service's response body, cut off after its first 4 KB */
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
 * the contract. The example service worker expects `PushPayload` JSON and will
 * throw on anything else — which is also why the send functions take this
 * wrapper rather than a bare string: a misdirected string would type-check,
 * deliver, and only fail inside `event.data.json()` on the device.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/migrate-from-web-push/ | Migrate from web-push}
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
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/collapse-notifications/ | Collapse and expire notifications}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8030#section-5.4 | RFC 8030 §5.4}
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

// Malformed subscription input throws a plain Error, never the TypeError that
// `new URL` or a missing `keys` would, so TypeError means the network alone.
const subscriptionKeys = ({ keys }: PushSubscriptionData): [p256dh: string, auth: string] => {
	if (typeof keys?.p256dh !== "string" || typeof keys.auth !== "string") {
		throw new Error("Invalid subscription: missing its p256dh or auth key");
	}
	return [keys.p256dh, keys.auth];
};

/** The JWT `aud` claim is the push service origin, not the full endpoint. */
const pushServiceOrigin = (endpoint: string): string => {
	if (!URL.canParse(endpoint)) {
		throw new Error("Invalid subscription endpoint: not a URL");
	}
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
const DEFAULT_TTL_S = 86400;
const DEFAULT_VAPID_EXPIRATION_S = 43200;

// setTimeout's ceiling, which AbortSignal.timeout shares: Node fires anything
// larger after 1ms, and throws on fractions, hence the rounding up.
const MAX_TIMEOUT_MS = 2 ** 31 - 1;
const wholeTimeoutMs = (timeoutMs: number): number => Math.ceil(timeoutMs);

/** RFC 8030 §5.2: `TTL` is delta-seconds, a non-negative integer. */
const wholeTtl = (ttl: number): number => Math.floor(ttl);

const assertValidTimeout = (timeoutMs: number): void => {
	const wholeMs = wholeTimeoutMs(timeoutMs);
	if (Number.isNaN(wholeMs) || wholeMs < 1 || wholeMs > MAX_TIMEOUT_MS) {
		throw new Error(`timeoutMs must be from 1 to ${MAX_TIMEOUT_MS} milliseconds`);
	}
};

const assertValidTtl = (ttl: number | undefined): void => {
	if (ttl !== undefined && (!Number.isSafeInteger(wholeTtl(ttl)) || ttl < 0)) {
		throw new Error("ttl must be a number of seconds, 0 or more");
	}
};

const assertValidSendOptions = ({
	topic,
	ttl,
	timeoutMs = DEFAULT_TIMEOUT_MS,
}: SendPushOptions): void => {
	assertValidTopic(topic);
	assertValidTtl(ttl);
	assertValidTimeout(timeoutMs);
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

/**
 * Push services answer in a few hundred bytes. The endpoint is chosen by the
 * subscriber, so without a cap a hostile one could stream an unbounded body
 * into memory on every send.
 */
const MAX_RESPONSE_BODY_BYTES = 4096;

const readBodyPrefix = async (response: Response): Promise<string> => {
	if (!response.body) {
		return "";
	}
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let text = "";
	let bytesRead = 0;
	while (bytesRead < MAX_RESPONSE_BODY_BYTES) {
		// oxlint-disable-next-line no-await-in-loop -- a stream yields its chunks in order
		const { done, value } = await reader.read();
		if (done) {
			return text + decoder.decode();
		}
		text += decoder.decode(value.subarray(0, MAX_RESPONSE_BODY_BYTES - bytesRead), {
			stream: true,
		});
		bytesRead += value.length;
	}
	// The status is already known, so a cancel that fails can't change the outcome.
	// Skipping the decoder's flush drops a character cut at the cap instead of
	// ending the text on U+FFFD.
	reader.cancel().catch(ignore);
	return text;
};

const ignore = (): void => {};

const postToPushService = async (
	subscription: PushSubscriptionData,
	payloadBytes: Uint8Array,
	jwt: string,
	vapidPublicKey: string,
	options: SendPushOptions,
): Promise<boolean> => {
	const {
		logger,
		ttl = DEFAULT_TTL_S,
		urgency,
		topic,
		signal,
		timeoutMs = DEFAULT_TIMEOUT_MS,
	} = options;

	const encryptedPayload = await encryptPayload(
		payloadBytes,
		subscription.keys.p256dh,
		subscription.keys.auth,
	);

	const response = await fetch(subscription.endpoint, {
		method: "POST",
		headers: buildPushHeaders({ jwt, vapidPublicKey, ttl: wholeTtl(ttl), urgency, topic }),
		body: encryptedPayload,
		signal: requestSignal(signal, wholeTimeoutMs(timeoutMs)),
	});

	// A delivered or gone send is settled by its status. Waiting on the body
	// would let a slow one time out a message the push service already accepted.
	const settled = response.ok || isSubscriptionGone(response.status);
	if (settled && !logger?.debug) {
		response.body?.cancel().catch(ignore);
		return response.ok;
	}

	const responseText = await readBodyPrefix(response);

	logger?.debug?.("Push response", {
		endpoint: subscription.endpoint.slice(0, 50),
		status: response.status,
		statusText: response.statusText,
		body: responseText.slice(0, 200),
	});

	if (settled) {
		return response.ok;
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
 * @param payload A {@link PushPayload} is JSON-serialized; a {@link rawPayload}
 * wrapper is encrypted and sent verbatim
 * @returns `true` once the push service accepts the message, `false` when the
 * subscription is gone (404/410) and should be deleted from your store
 * @throws {WebPushError} on rate limits (429) and other push service errors
 * @throws {TypeError} when `fetch` never reaches the push service: DNS, TLS, a dropped connection
 * @throws {DOMException} `TimeoutError` after `timeoutMs`
 * @throws the `signal`'s abort reason when it aborts: an `AbortError` `DOMException`
 * unless you passed `abort()` a reason of your own
 * @throws {Error} on invalid input: VAPID config, payload size, `topic`, `ttl`,
 * `timeoutMs`, or a non-`https:` endpoint
 * @example
 * ```ts
 * const delivered = await sendPushNotification(subscription, payload, vapid);
 * if (!delivered) await removeFromStore(subscription.endpoint);
 * ```
 * @see {@link https://web-push.thelazyweb.dev/guides/handle-errors/ | Handle errors and retries}
 * @see {@link https://web-push.thelazyweb.dev/guides/collapse-notifications/ | Collapse and expire notifications}
 */
export const sendPushNotification = async (
	subscription: PushSubscriptionData,
	payload: PushPayload | RawPushPayload,
	vapid: VapidConfig,
	options: SendPushOptions = {},
): Promise<boolean> => {
	assertValidSendOptions(options);

	// Reject bad input *before* signing the VAPID JWT — no point paying for an
	// ECDSA signature on a request we'll refuse.
	const payloadBytes = encodePayload(payload);
	validatePushInputs(payloadBytes, ...subscriptionKeys(subscription));

	// JWT expiry is independent of the message TTL: push services reject tokens
	// valid for more than 24h, whereas TTL (message retention) is routinely longer.
	const jwt = await createVapidJwt({
		audience: pushServiceOrigin(subscription.endpoint),
		subject: vapid.subject,
		publicKey: vapid.publicKey,
		privateKey: vapid.privateKey,
		expiration: options.vapidExpiration ?? DEFAULT_VAPID_EXPIRATION_S,
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
 * rather than per message, since the token is scoped to the origin, and
 * re-signed at half its lifetime, so a batch that outlasts `vapidExpiration`
 * never sends an expired one. Aborting `options.signal` stops workers from
 * starting new sends; subscriptions never attempted count toward none of the three.
 *
 * @param payload A {@link PushPayload} is JSON-serialized; a {@link rawPayload}
 * wrapper is encrypted and sent verbatim
 * @throws {Error} on caller input — invalid VAPID config, oversized payload,
 * invalid `topic`, `ttl`, `concurrency`, or `timeoutMs` — before anything is sent.
 * A non-`https:` endpoint is per-subscription data and lands in `failed`.
 * @example
 * ```ts
 * const { delivered, gone, failed } = await sendPushBatch(subscriptions, payload, vapid);
 * await removeFromStore(gone);
 * for (const { endpoint, error } of failed) console.warn("push failed", endpoint, error);
 * ```
 * @see {@link https://web-push.thelazyweb.dev/guides/send-to-many/ | Send to many}
 * @see {@link https://web-push.thelazyweb.dev/guides/handle-errors/ | Handle errors and retries}
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
	assertValidSendOptions(sendOptions);

	const payloadBytes = encodePayload(payload);
	assertPayloadWithinLimit(payloadBytes);

	const vapidExpiration = sendOptions.vapidExpiration ?? DEFAULT_VAPID_EXPIRATION_S;
	const vapidJwtFor = (audience: string): Promise<string> =>
		createVapidJwt({
			audience,
			subject: vapid.subject,
			publicKey: vapid.publicKey,
			privateKey: vapid.privateKey,
			expiration: vapidExpiration,
		});

	// Sign a throwaway token so a bad VAPID config (subject, expiration, key
	// shape) throws once here instead of repeating in `failed` per subscription.
	await vapidJwtFor("https://push.invalid");

	// Caching the promise, not the token, so concurrent workers hitting the
	// same origin share one signature instead of racing to sign their own.
	const jwtByOrigin = new Map<string, { jwt: Promise<string>; refreshAt: number }>();
	const cachedJwtFor = (origin: string): Promise<string> => {
		const cached = jwtByOrigin.get(origin);
		if (cached && Date.now() < cached.refreshAt) {
			return cached.jwt;
		}
		// The JWT's `exp` counts from the whole second it was signed in, so the
		// refresh does too; counting from now could land it after `exp`.
		const signedAtMs = Math.floor(Date.now() / 1000) * 1000;
		const jwt = vapidJwtFor(origin);
		jwtByOrigin.set(origin, { jwt, refreshAt: signedAtMs + (vapidExpiration * 1000) / 2 });
		return jwt;
	};

	let delivered = 0;
	const gone: string[] = [];
	const failed: SendPushBatchResult["failed"] = [];

	// Rows are often cast from a database or JSON, so a null one has to land in
	// `failed` rather than reject the whole batch.
	const sendOne = async (subscription: PushSubscriptionData | null | undefined): Promise<void> => {
		try {
			if (!subscription) {
				throw new Error("Invalid subscription: not an object");
			}
			validatePushInputs(payloadBytes, ...subscriptionKeys(subscription));
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
			failed.push({ endpoint: subscription?.endpoint ?? "", error });
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
