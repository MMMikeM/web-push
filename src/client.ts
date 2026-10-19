/**
 * Browser-only. These reach for `window`, `navigator`, and `Notification`, so
 * they throw anywhere else — server code wants `./send`.
 */

import type { PushSubscriptionData } from "./types";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "./vapid";

export type { PushSubscriptionData };

/**
 * Check if push notifications are supported in this browser.
 */
export const isPushSupported = (): boolean =>
	"serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

/**
 * Get the current notification permission status.
 */
export const getNotificationPermission = (): NotificationPermission => Notification.permission;

/**
 * Request permission to show notifications.
 */
export const requestNotificationPermission = (): Promise<NotificationPermission> =>
	Notification.requestPermission();

/**
 * The outcome of {@link subscribe}: a subscription, or why there is none.
 */
export type SubscribeResult =
	| {
			status: "subscribed";
			subscription: PushSubscription;
			/** Whether this call created the subscription: first subscribe, or key rotation */
			isNew: boolean;
			/** Endpoint a key rotation unsubscribed, when it differs from the new one; delete its record */
			replacedEndpoint?: string;
	  }
	| { status: "unsupported" }
	| { status: "denied" };

// Browsers that predate `options.applicationServerKey` report null; treat that
// as a match — discarding a working subscription is worse than keeping it.
const isBoundToKey = (subscription: PushSubscription, key: Uint8Array): boolean => {
	const bound = subscription.options.applicationServerKey;
	if (!bound) {
		return true;
	}
	const boundBytes = new Uint8Array(bound);
	return boundBytes.length === key.length && boundBytes.every((byte, i) => byte === key[i]);
};

// Checked before the stale-key comparison: an empty or wrong-length key never
// matches, so it would otherwise unsubscribe a working subscription as a "rotation".
const decodeVapidPublicKey = (vapidPublicKey: string): Uint8Array<ArrayBuffer> => {
	const key = urlBase64ToUint8Array(vapidPublicKey);
	if (key.length !== 65 || key[0] !== 0x04) {
		throw new Error("VAPID public key must be a 65-byte uncompressed P-256 point");
	}
	return key;
};

/**
 * Subscribe to push notifications, prompting for permission if needed.
 *
 * Reuses an existing subscription when it was created with the same VAPID key.
 * If the key has changed, the stale subscription is unsubscribed and replaced,
 * since the push service would reject it anyway, and its endpoint comes back as
 * `replacedEndpoint` so the server can delete that record. `isNew` reports whether this
 * call created the subscription (first subscribe or key rotation). Send the
 * subscription to your server either way: gating the upload on `isNew` means
 * one failed request strands a subscription your server never hears about.
 *
 * @param vapidPublicKey - The server's VAPID public key (URL-safe base64)
 * @throws {Error} if `vapidPublicKey` is not a 65-byte uncompressed P-256 point;
 * checked before the permission prompt and before any existing subscription is touched.
 * @throws {DOMException} if the browser or push service refuses the subscription, or
 * the stale-key subscription can't be unsubscribed during a rotation.
 * @example
 * ```ts
 * const result = await subscribe(vapidPublicKey);
 * if (result.status === "subscribed") {
 *   await sendSubscriptionToServer(result.subscription);
 * }
 * ```
 */
export const subscribe = async (vapidPublicKey: string): Promise<SubscribeResult> => {
	if (!isPushSupported()) {
		return { status: "unsupported" };
	}

	const applicationServerKey = decodeVapidPublicKey(vapidPublicKey);

	const permission = await requestNotificationPermission();
	if (permission !== "granted") {
		return { status: "denied" };
	}

	const registration = await navigator.serviceWorker.ready;
	const existingSubscription = await registration.pushManager.getSubscription();
	if (existingSubscription) {
		if (isBoundToKey(existingSubscription, applicationServerKey)) {
			return { status: "subscribed", subscription: existingSubscription, isNew: false };
		}
		await existingSubscription.unsubscribe();
	}

	const subscription = await registration.pushManager.subscribe({
		userVisibleOnly: true,
		applicationServerKey,
	});
	const staleEndpoint = existingSubscription?.endpoint;
	// A push service may reissue the same endpoint; reporting it would have the
	// caller delete the record it just saved.
	return staleEndpoint && staleEndpoint !== subscription.endpoint
		? { status: "subscribed", subscription, isNew: true, replacedEndpoint: staleEndpoint }
		: { status: "subscribed", subscription, isNew: true };
};

/**
 * Subscribe to push notifications, prompting for permission if needed.
 *
 * @deprecated Renamed to {@link subscribe} — same behavior, symmetric with
 * `unsubscribe`.
 */
export const subscribeToPush = subscribe;

/**
 * Get the current push subscription if it exists.
 */
export const getCurrentSubscription = async (): Promise<PushSubscription | null> => {
	if (!isPushSupported()) {
		return null;
	}

	// Not `ready`: it never settles without a registered worker, and no
	// registration means no subscription.
	const registration = await navigator.serviceWorker.getRegistration();
	return registration ? registration.pushManager.getSubscription() : null;
};

/**
 * Unsubscribe from push notifications.
 *
 * Resolves `true` when there is nothing to unsubscribe from — no current
 * subscription, or push not supported in this browser.
 *
 * @deprecated Use {@link unsubscribe} instead: it returns the
 * unsubscribed endpoint, which the server needs to prune its matching
 * subscription record — this boolean drops it.
 * @throws {DOMException} if the browser rejects the unsubscribe (e.g. the push
 * service is unreachable), where `unsubscribe` still resolves the endpoint.
 */
export const unsubscribeFromPush = async (): Promise<boolean> => {
	const subscription = await getCurrentSubscription();
	return subscription ? subscription.unsubscribe() : true;
};

/**
 * Unsubscribe from push notifications, returning the unsubscribed endpoint.
 *
 * Resolves to the subscription's endpoint so the caller can prune the matching
 * server-side record, or `null` when there was nothing to unsubscribe — no
 * current subscription, or push not supported in this browser. The endpoint is
 * returned even if the browser reports the unsubscribe as failed or rejects
 * (e.g. the push service is unreachable): the caller's intent is to stop
 * receiving pushes, and removing the server record achieves that regardless.
 */
export const unsubscribe = async (): Promise<string | null> => {
	const subscription = await getCurrentSubscription();
	if (!subscription) {
		return null;
	}

	const { endpoint } = subscription;
	await subscription.unsubscribe().catch(() => false);
	return endpoint;
};

const requireKey = (subscription: PushSubscription, name: "p256dh" | "auth"): ArrayBuffer => {
	const key = subscription.getKey(name);
	if (!key) {
		throw new Error(`Subscription is missing its ${name} key`);
	}
	return key;
};

/**
 * Convert a PushSubscription to serializable data for sending to the server.
 *
 * @throws {Error} if the subscription is missing its `p256dh` or `auth` key.
 */
export const serializeSubscription = (subscription: PushSubscription): PushSubscriptionData => ({
	endpoint: subscription.endpoint,
	keys: {
		p256dh: arrayBufferToUrlBase64(requireKey(subscription, "p256dh")),
		auth: arrayBufferToUrlBase64(requireKey(subscription, "auth")),
	},
});

const sendJson = async (endpoint: string, method: string, body: unknown): Promise<boolean> => {
	const response = await fetch(endpoint, {
		method,
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	return response.ok;
};

/**
 * Send a push subscription to a server endpoint.
 */
export const sendSubscriptionToServer = async (
	subscription: PushSubscription,
	endpoint = "/api/push/subscribe",
): Promise<boolean> => sendJson(endpoint, "POST", serializeSubscription(subscription));

/**
 * Remove a push subscription from a server endpoint.
 */
export const removeSubscriptionFromServer = (
	subscriptionEndpoint: string,
	serverEndpoint = "/api/push/subscribe",
): Promise<boolean> => sendJson(serverEndpoint, "DELETE", { endpoint: subscriptionEndpoint });

const arrayBufferToUrlBase64 = (buffer: ArrayBuffer): string =>
	uint8ArrayToUrlBase64(new Uint8Array(buffer));
