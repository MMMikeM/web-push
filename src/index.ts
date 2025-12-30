/**
 * Web Push notification library.
 *
 * Server-side: VAPID authentication and RFC 8291 encryption
 * Client-side: Push subscription management
 */

// Client-side exports
export {
	getCurrentSubscription,
	getNotificationPermission,
	isPushSupported,
	removeSubscriptionFromServer,
	requestNotificationPermission,
	sendSubscriptionToServer,
	serializeSubscription,
	subscribeToPush,
	unsubscribeFromPush,
} from "./client";
// Server-side exports
export { sendPushNotification } from "./send";
// Types
export type {
	Logger,
	PushPayload,
	PushSubscriptionData,
	SendPushOptions,
	VapidConfig,
} from "./types";
export type { VapidJwtOptions } from "./vapid";
export {
	createVapidJwt,
	generateVapidKeys,
	uint8ArrayToUrlBase64,
	urlBase64ToUint8Array,
} from "./vapid";
