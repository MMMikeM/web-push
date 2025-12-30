/**
 * Client-side push notification utilities.
 *
 * These functions run in the browser and handle the subscription flow
 * for push notifications.
 */

import type { PushSubscriptionData } from "./types";
import { urlBase64ToUint8Array } from "./vapid";

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
 * Subscribe to push notifications.
 *
 * @param vapidPublicKey - The server's VAPID public key (URL-safe base64)
 * @returns The push subscription to send to the server
 */
export const subscribeToPush = async (vapidPublicKey: string): Promise<PushSubscription | null> => {
	if (!isPushSupported()) {
		console.warn("Push notifications not supported");
		return null;
	}

	const permission = await requestNotificationPermission();
	if (permission !== "granted") {
		console.warn("Notification permission denied");
		return null;
	}

	const registration = await navigator.serviceWorker.ready;

	// Check for existing subscription
	const existingSubscription = await registration.pushManager.getSubscription();
	if (existingSubscription) {
		return existingSubscription;
	}

	// Create new subscription
	const subscription = await registration.pushManager.subscribe({
		userVisibleOnly: true,
		applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
	});

	return subscription;
};

/**
 * Unsubscribe from push notifications.
 */
export const unsubscribeFromPush = async (): Promise<boolean> => {
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

/**
 * Convert a PushSubscription to serializable data for sending to the server.
 */
export const serializeSubscription = (subscription: PushSubscription): PushSubscriptionData => ({
	endpoint: subscription.endpoint,
	keys: {
		p256dh: arrayBufferToUrlBase64(subscription.getKey("p256dh")!),
		auth: arrayBufferToUrlBase64(subscription.getKey("auth")!),
	},
});

/**
 * Send a push subscription to a server endpoint.
 *
 * @param subscription - The browser's push subscription
 * @param endpoint - The server endpoint URL (default: /api/push/subscribe)
 */
export const sendSubscriptionToServer = async (
	subscription: PushSubscription,
	endpoint = "/api/push/subscribe",
): Promise<boolean> => {
	const response = await fetch(endpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify(serializeSubscription(subscription)),
	});

	return response.ok;
};

/**
 * Remove a push subscription from a server endpoint.
 *
 * @param subscriptionEndpoint - The subscription endpoint to remove
 * @param serverEndpoint - The server API endpoint URL (default: /api/push/subscribe)
 */
export const removeSubscriptionFromServer = async (
	subscriptionEndpoint: string,
	serverEndpoint = "/api/push/subscribe",
): Promise<boolean> => {
	const response = await fetch(serverEndpoint, {
		method: "DELETE",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ endpoint: subscriptionEndpoint }),
	});

	return response.ok;
};

/**
 * Convert an ArrayBuffer to URL-safe base64.
 */
const arrayBufferToUrlBase64 = (buffer: ArrayBuffer): string => {
	const bytes = new Uint8Array(buffer);
	const binary = String.fromCharCode(...bytes);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
