import { describe, expect, it } from "vitest";
import * as pkg from "../src/index";

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
	const serverExports = ["sendPushNotification", "WebPushError"];
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
});
