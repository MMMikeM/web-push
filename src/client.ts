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
 *
 * @returns The permission result
 */
export const requestNotificationPermission = (): Promise<NotificationPermission> =>
	Notification.requestPermission();

/**
 * The outcome of {@link subscribeToPush}: a subscription, or why there is none.
 */
export type SubscribeResult =
	| {
			status: "subscribed";
			subscription: PushSubscription;
			/** Whether this call created the subscription: first subscribe, or key rotation */
			isNew: boolean;
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

/**
 * Subscribe to push notifications, prompting for permission if needed.
 *
 * Reuses an existing subscription when it was created with the same VAPID key.
 * If the key has changed, the stale subscription is unsubscribed and replaced,
 * since the push service would reject it anyway. `isNew` reports whether this
 * call created the subscription (first subscribe or key rotation). Send the
 * subscription to your server either way: gating the upload on `isNew` means
 * one failed request strands a subscription your server never hears about.
 *
 * @param vapidPublicKey - The server's VAPID public key (URL-safe base64)
 * @example
 * ```ts
 * const result = await subscribeToPush(vapidPublicKey);
 * if (result.status === "subscribed") {
 *   await sendSubscriptionToServer(result.subscription);
 * }
 * ```
 */
export const subscribeToPush = async (vapidPublicKey: string): Promise<SubscribeResult> => {
	if (!isPushSupported()) {
		return { status: "unsupported" };
	}

	const permission = await requestNotificationPermission();
	if (permission !== "granted") {
		return { status: "denied" };
	}

	const registration = await navigator.serviceWorker.ready;
	const applicationServerKey = urlBase64ToUint8Array(vapidPublicKey);

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
	return { status: "subscribed", subscription, isNew: true };
};

/**
 * Unsubscribe from push notifications.
 *
 * Resolves `true` when there is nothing to unsubscribe from — no current
 * subscription, or push not supported in this browser.
 */
export const unsubscribeFromPush = async (): Promise<boolean> => {
	if (!isPushSupported()) {
		return true;
	}

	const registration = await navigator.serviceWorker.ready;
	const subscription = await registration.pushManager.getSubscription();

	if (!subscription) {
		return true;
	}

	return subscription.unsubscribe();
};

/**
 * Get the current push subscription if it exists.
 */
export const getCurrentSubscription = async (): Promise<PushSubscription | null> => {
	if (!isPushSupported()) {
		return null;
	}

	const registration = await navigator.serviceWorker.ready;
	return registration.pushManager.getSubscription();
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
 *
 * @param subscription - The browser's push subscription
 * @param endpoint - The server endpoint URL (default: /api/push/subscribe)
 */
export const sendSubscriptionToServer = async (
	subscription: PushSubscription,
	endpoint = "/api/push/subscribe",
): Promise<boolean> => sendJson(endpoint, "POST", serializeSubscription(subscription));

/**
 * Remove a push subscription from a server endpoint.
 *
 * @param subscriptionEndpoint - The subscription endpoint to remove
 * @param serverEndpoint - The server API endpoint URL (default: /api/push/subscribe)
 */
export const removeSubscriptionFromServer = (
	subscriptionEndpoint: string,
	serverEndpoint = "/api/push/subscribe",
): Promise<boolean> => sendJson(serverEndpoint, "DELETE", { endpoint: subscriptionEndpoint });

/**
 * Convert an ArrayBuffer to URL-safe base64.
 */
const arrayBufferToUrlBase64 = (buffer: ArrayBuffer): string =>
	uint8ArrayToUrlBase64(new Uint8Array(buffer));
