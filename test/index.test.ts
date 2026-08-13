import { describe, expect, it } from "vite-plus/test";
import * as clientEntry from "../src/client";
import * as pkg from "../src/index";
import * as sendEntry from "../src/send";
import * as vapidEntry from "../src/vapid";

describe("index barrel", () => {
	const clientExports = [
		"getCurrentSubscription",
		"getNotificationPermission",
		"isPushSupported",
		"removeSubscriptionFromServer",
		"requestNotificationPermission",
		"sendSubscriptionToServer",
		"serializeSubscription",
		"subscribeToPush",
		"unsubscribeFromPush",
	];
	const serverExports = ["rawPayload", "sendPushBatch", "sendPushNotification", "WebPushError"];
	const vapidExports = [
		"createVapidJwt",
		"generateVapidKeys",
		"uint8ArrayToUrlBase64",
		"urlBase64ToUint8Array",
	];
	const expected = [...clientExports, ...serverExports, ...vapidExports];

	it.each(expected)("re-exports %s as a function", (name) => {
		expect(typeof (pkg as Record<string, unknown>)[name]).toBe("function");
	});

	it("exports exactly the expected public surface", () => {
		expect(Object.keys(pkg).toSorted()).toEqual(expected.toSorted());
	});

	it("each subpath entry exports exactly its slice of that surface", () => {
		expect(Object.keys(clientEntry).toSorted()).toEqual(clientExports.toSorted());
		expect(Object.keys(sendEntry).toSorted()).toEqual(serverExports.toSorted());
		expect(Object.keys(vapidEntry).toSorted()).toEqual(vapidExports.toSorted());
	});
});
