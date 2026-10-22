/**
 * Browser-only: a page, or a service worker that passes its own `registration`.
 * Elsewhere the permission helpers throw — server code wants `./send`.
 */

import type { PushSubscriptionData } from "./types";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "./vapid";

export type { PushSubscriptionData };

/**
 * Check if push notifications are supported in this browser.
 */
export const isPushSupported = (): boolean =>
	"serviceWorker" in navigator && "PushManager" in globalThis && "Notification" in globalThis;

/**
 * Get the current notification permission status.
 *
 * @returns `"default"` until the user has been asked.
 * @throws {ReferenceError} where there is no `Notification` global, such as on a server.
 */
export const getNotificationPermission = (): NotificationPermission => Notification.permission;

/**
 * Request permission to show notifications, prompting the user if they haven't been asked.
 *
 * @returns `"default"` again if the user dismissed the prompt.
 * @throws {TypeError} in a service worker, where `Notification.requestPermission` doesn't exist.
 * @throws {ReferenceError} where there is no `Notification` global, such as on a server.
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
			/**
			 * Whether this call created the subscription: first subscribe, or
			 * replacing one bound to another VAPID key or `userVisibleOnly` mode
			 */
			isNew: boolean;
	  }
	| { status: "unsupported" }
	| { status: "denied" };

/**
 * Which service worker registration to act on.
 */
export type RegistrationOption = {
	/**
	 * Defaults to `navigator.serviceWorker.ready`; a service worker passes
	 * `self.registration`.
	 */
	registration?: ServiceWorkerRegistration;
};

/**
 * Where and how {@link subscribe} subscribes. The defaults suit a page.
 *
 * @see {@link https://mmmikem.github.io/web-push/guides/extension-service-workers/ | Extension service workers}
 */
export type SubscribeOptions = RegistrationOption & {
	/**
	 * Whether every push must show a notification. Defaults to `true`; only a
	 * Chrome extension's service worker (Chrome 121+) may pass `false`.
	 */
	userVisibleOnly?: boolean;
};

const isPushAvailable = (registration: ServiceWorkerRegistration | undefined): boolean =>
	registration ? "PushManager" in globalThis && "Notification" in globalThis : isPushSupported();

// `Notification.requestPermission` is Window-only, so a service worker can only
// read the permission it already holds. Not `pushManager.permissionState`: Chrome
// rejects it for `userVisibleOnly: false`, even in extensions.
// https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/modules/push_messaging/push_messaging_bridge.cc
const isPermissionGranted = async (): Promise<boolean> =>
	("requestPermission" in Notification
		? await requestNotificationPermission()
		: getNotificationPermission()) === "granted";

// A key that can't be a P-256 public key (a missing env var, the private key
// pasted by mistake) must fail before the existing subscription is touched:
// otherwise it is torn down and the browser then refuses the replacement.
const INVALID_VAPID_PUBLIC_KEY = "vapidPublicKey must be a 65-byte uncompressed P-256 public key";

const decodeVapidPublicKey = (vapidPublicKey: string): Uint8Array<ArrayBuffer> => {
	let key: Uint8Array<ArrayBuffer>;
	try {
		key = urlBase64ToUint8Array(vapidPublicKey);
	} catch (cause) {
		throw new Error(INVALID_VAPID_PUBLIC_KEY, { cause });
	}
	if (key.length !== 65 || key[0] !== 0x04) {
		throw new Error(INVALID_VAPID_PUBLIC_KEY);
	}
	return key;
};

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

// Not every browser reports `options.userVisibleOnly`. Treating its absence as a
// mismatch would replace the subscription, and change its endpoint, on every call.
const hasVisibility = (subscription: PushSubscription, userVisibleOnly: boolean): boolean => {
	const bound = subscription.options.userVisibleOnly;
	return bound === undefined || bound === userVisibleOnly;
};

/**
 * Subscribe to push notifications, prompting for permission if needed.
 *
 * Reuses an existing subscription when it was created with the same VAPID key
 * and `userVisibleOnly` mode. Otherwise the stale subscription is unsubscribed
 * and replaced, since the push service would reject it anyway. `isNew` reports
 * whether this call created the subscription. Send the subscription to your
 * server either way: gating the upload on `isNew` means one failed request
 * strands a subscription your server never hears about.
 *
 * In a service worker, which cannot prompt, pass `self.registration`; the
 * permission it already holds decides between `subscribed` and `denied`.
 *
 * @param vapidPublicKey - The server's VAPID public key (URL-safe base64)
 * @throws {Error} when `vapidPublicKey` isn't a 65-byte P-256 public key, checked before
 * anything else, so a misconfigured key never costs a subscriber their subscription.
 * @throws {DOMException} `InvalidCharacterError` when `vapidPublicKey` isn't valid base64url.
 * @throws {DOMException} when the browser refuses the subscription: `NotAllowedError`
 * for `userVisibleOnly: false` anywhere but a Chrome extension's service worker,
 * `AbortError` when its push service is unavailable, as in Brave by default.
 * @example
 * ```ts
 * const result = await subscribe(vapidPublicKey);
 * if (result.status === "subscribed") {
 *   await sendSubscriptionToServer(result.subscription);
 * }
 * ```
 * @example
 * ```ts
 * // Chrome extension service worker
 * const result = await subscribe(vapidPublicKey, {
 *   registration: self.registration,
 *   userVisibleOnly: false,
 * });
 * ```
 * @see {@link https://mmmikem.github.io/web-push/guides/rotate-vapid-keys/ | Rotate VAPID keys}
 * @see {@link https://mmmikem.github.io/web-push/guides/extension-service-workers/ | Extension service workers}
 */
export const subscribe = async (
	vapidPublicKey: string,
	{ registration, userVisibleOnly = true }: SubscribeOptions = {},
): Promise<SubscribeResult> => {
	const applicationServerKey = decodeVapidPublicKey(vapidPublicKey);
	if (!isPushAvailable(registration)) {
		return { status: "unsupported" };
	}

	// Prompt before waiting on the registration: on a first visit the worker may
	// still be installing, and a prompt delayed past the user gesture can be blocked.
	if (!(await isPermissionGranted())) {
		return { status: "denied" };
	}

	const target = registration ?? (await navigator.serviceWorker.ready);
	const existingSubscription = await target.pushManager.getSubscription();
	if (existingSubscription) {
		if (
			isBoundToKey(existingSubscription, applicationServerKey) &&
			hasVisibility(existingSubscription, userVisibleOnly)
		) {
			return { status: "subscribed", subscription: existingSubscription, isNew: false };
		}
		await existingSubscription.unsubscribe();
	}

	const subscription = await target.pushManager.subscribe({
		userVisibleOnly,
		applicationServerKey,
	});
	return { status: "subscribed", subscription, isNew: true };
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
export const getCurrentSubscription = async ({
	registration,
}: RegistrationOption = {}): Promise<PushSubscription | null> => {
	if (!isPushAvailable(registration)) {
		return null;
	}

	const target = registration ?? (await navigator.serviceWorker.ready);
	return target.pushManager.getSubscription();
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
export const unsubscribe = async (options: RegistrationOption = {}): Promise<string | null> => {
	const subscription = await getCurrentSubscription(options);
	if (!subscription) {
		return null;
	}

	const { endpoint } = subscription;
	try {
		await subscription.unsubscribe();
	} catch {
		// The endpoint is the contract; a failed deregistration must not hide it.
	}
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

const sendJson = async (
	endpoint: string,
	defaultMethod: string,
	body: unknown,
	init: Omit<RequestInit, "body">,
): Promise<boolean> => {
	const headers = new Headers(init.headers);
	if (!headers.has("Content-Type")) {
		headers.set("Content-Type", "application/json");
	}
	const response = await fetch(endpoint, {
		...init,
		method: init.method ?? defaultMethod,
		headers,
		body: JSON.stringify(body),
	});
	return response.ok;
};

/**
 * Send a push subscription to a server endpoint, resolving to whether it answered 2xx.
 *
 * `init` adds to the request: an `Authorization` header, `credentials`, a `signal`.
 * Its `method` replaces `POST`, and its headers merge with `Content-Type:
 * application/json`. Cross-origin, the server must allow those headers in its CORS
 * preflight; an extension calling a host in its `host_permissions` skips CORS.
 *
 * @param subscription Serialized with {@link serializeSubscription} for the body.
 * @param endpoint Defaults to `/api/push/subscribe`, resolved against the page; an
 * extension passes an absolute URL.
 * @param init Merged into the upload's request.
 * @throws {Error} if the subscription is missing its `p256dh` or `auth` key.
 * @throws {TypeError} on a network failure.
 * @throws {DOMException} `AbortError` when `init.signal` aborts.
 * @see {@link https://mmmikem.github.io/web-push/guides/authenticated-uploads/ | Authenticated uploads}
 */
export const sendSubscriptionToServer = async (
	subscription: PushSubscription,
	endpoint = "/api/push/subscribe",
	init: Omit<RequestInit, "body"> = {},
): Promise<boolean> => sendJson(endpoint, "POST", serializeSubscription(subscription), init);

/**
 * Remove a push subscription from a server endpoint, resolving to whether it answered 2xx.
 *
 * Sends `{ endpoint }` as JSON.
 *
 * @param subscriptionEndpoint The endpoint to forget, as {@link unsubscribe} resolved it.
 * @param serverEndpoint Defaults to `/api/push/subscribe`, resolved against the page.
 * @param init As for {@link sendSubscriptionToServer}, with `method` replacing `DELETE`.
 * @throws {TypeError} on a network failure.
 * @throws {DOMException} `AbortError` when `init.signal` aborts.
 * @see {@link https://mmmikem.github.io/web-push/guides/authenticated-uploads/ | Authenticated uploads}
 */
export const removeSubscriptionFromServer = (
	subscriptionEndpoint: string,
	serverEndpoint = "/api/push/subscribe",
	init: Omit<RequestInit, "body"> = {},
): Promise<boolean> => sendJson(serverEndpoint, "DELETE", { endpoint: subscriptionEndpoint }, init);

const arrayBufferToUrlBase64 = (buffer: ArrayBuffer): string =>
	uint8ArrayToUrlBase64(new Uint8Array(buffer));
