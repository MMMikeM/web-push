/**
 * The HTTP half of a push: VAPID auth (RFC 8292) over an aes128gcm-encrypted
 * body (RFC 8291), plus the status handling that decides delivered / gone / error.
 */

import { encryptPayload, validatePushInputs } from "./encrypt";
import type { PushPayload, PushSubscriptionData, SendPushOptions, VapidConfig } from "./types";
import { createVapidJwt } from "./vapid";

export type { PushSubscriptionData, PushPayload, VapidConfig, SendPushOptions };

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

/**
 * Send a push notification to a subscription endpoint.
 *
 * @param subscription - The push subscription to send to
 * @param payload - The notification payload
 * @param vapid - VAPID configuration
 * @param options - Optional settings (logger, TTL, VAPID expiration, urgency, topic)
 * @returns true if successful, false if subscription is invalid (should be deleted)
 * @throws {WebPushError} on rate limits (429) and other push service errors
 */
export const sendPushNotification = async (
	subscription: PushSubscriptionData,
	payload: PushPayload,
	vapid: VapidConfig,
	options: SendPushOptions = {},
): Promise<boolean> => {
	const { logger, ttl = 86400, vapidExpiration = 43200, urgency, topic } = options;

	assertValidTopic(topic);

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
		expiration: vapidExpiration,
	});

	const encryptedPayload = await encryptPayload(
		payloadBytes,
		subscription.keys.p256dh,
		subscription.keys.auth,
	);

	const response = await fetch(subscription.endpoint, {
		method: "POST",
		headers: buildPushHeaders({ jwt, vapidPublicKey: vapid.publicKey, ttl, urgency, topic }),
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
