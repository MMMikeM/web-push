import { afterEach, describe, expect, it, Mock, vi } from "vite-plus/test";
import {
	getCurrentSubscription,
	getNotificationPermission,
	isPushSupported,
	removeSubscriptionFromServer,
	requestNotificationPermission,
	sendSubscriptionToServer,
	serializeSubscription,
	subscribeToPush,
	unsubscribeFromPush,
} from "../src/client";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "../src/vapid";
import { headersOf, stubFetch } from "./helpers";

// A real PushSubscription, so fakes pass into client.ts without casts; the
// intersection keeps `unsubscribe` a typed mock the tests can assert on.
type FakeSubscription = PushSubscription & {
	unsubscribe: Mock<() => Promise<boolean>>;
};

const makeSubscription = (
	endpoint = "https://push.example.com/sub/1",
	p256dh = new Uint8Array([1, 2, 3, 4]),
	auth = new Uint8Array([9, 8, 7]),
): FakeSubscription => ({
	endpoint,
	expirationTime: null,
	options: { applicationServerKey: null, userVisibleOnly: true },
	unsubscribe: vi.fn<() => Promise<boolean>>(async () => true),
	getKey: (name: PushEncryptionKeyName) => (name === "p256dh" ? p256dh.buffer : auth.buffer),
	toJSON: () => ({ endpoint, expirationTime: null, keys: {} }),
});

type EnvOptions = {
	serviceWorker?: boolean;
	pushManager?: boolean;
	notification?: boolean;
	permission?: NotificationPermission;
	promptResult?: NotificationPermission;
	existing?: FakeSubscription | null;
};

function PushManager() {}

/** Stub the browser push globals client.ts reaches for. */
const setupPushEnv = (opts: EnvOptions = {}) => {
	const {
		serviceWorker = true,
		pushManager: hasPushManager = true,
		notification = true,
		permission = "granted",
		promptResult = permission,
		existing = null,
	} = opts;
	const created = makeSubscription("https://push.example.com/sub/new");

	// Stateful fake: subscribe/unsubscribe move `current`, so tests can exercise
	// the whole lifecycle instead of one pre-arranged state per call.
	let current = existing;
	const clearOnUnsubscribe = (sub: FakeSubscription) => {
		sub.unsubscribe.mockImplementation(async () => {
			current = null;
			return true;
		});
	};
	if (existing) {
		clearOnUnsubscribe(existing);
	}
	clearOnUnsubscribe(created);

	const pushManager = {
		getSubscription: vi.fn<() => Promise<FakeSubscription | null>>(async () => current),
		subscribe: vi.fn<(options?: PushSubscriptionOptionsInit) => Promise<FakeSubscription>>(
			async () => {
				current = created;
				return created;
			},
		),
	};
	const registration = { pushManager };

	const NotificationStub = {
		permission,
		requestPermission: vi.fn<() => Promise<NotificationPermission>>(async () => promptResult),
	};

	// `in window` / `in navigator` checks drive isPushSupported; each flag
	// removes exactly one of its three clauses.
	const windowStub: Record<string, unknown> = {};
	const navigatorStub: Record<string, unknown> = {};
	if (notification) {
		windowStub.Notification = NotificationStub;
	}
	if (hasPushManager) {
		windowStub.PushManager = PushManager;
	}
	if (serviceWorker) {
		navigatorStub.serviceWorker = { ready: Promise.resolve(registration) };
	}

	vi.stubGlobal("window", windowStub);
	vi.stubGlobal("navigator", navigatorStub);
	vi.stubGlobal("Notification", NotificationStub);

	return { pushManager, created, NotificationStub };
};

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("feature detection & permission", () => {
	it("isPushSupported is true when all APIs are present", () => {
		setupPushEnv();
		expect(isPushSupported()).toBe(true);
	});

	it.each([
		{ missing: "serviceWorker", opts: { serviceWorker: false } },
		{ missing: "PushManager", opts: { pushManager: false } },
		{ missing: "Notification", opts: { notification: false } },
	])("isPushSupported is false when only $missing is missing", ({ opts }) => {
		setupPushEnv(opts);
		expect(isPushSupported()).toBe(false);
	});

	it("getNotificationPermission reflects Notification.permission", () => {
		setupPushEnv({ permission: "denied" });
		expect(getNotificationPermission()).toBe("denied");
	});

	it("requestNotificationPermission delegates to Notification.requestPermission", async () => {
		const { NotificationStub } = setupPushEnv({ permission: "granted" });
		expect(await requestNotificationPermission()).toBe("granted");
		expect(NotificationStub.requestPermission).toHaveBeenCalledOnce();
	});
});

describe("subscribeToPush", () => {
	it("returns null and warns when push is unsupported", async () => {
		setupPushEnv({ serviceWorker: false });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		expect(await subscribeToPush("BPk")).toBeNull();
		expect(warn).toHaveBeenCalledWith("Push notifications not supported");
	});

	it("returns null and warns when the permission prompt is denied", async () => {
		setupPushEnv({ permission: "default", promptResult: "denied" });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		expect(await subscribeToPush("BPk")).toBeNull();
		expect(warn).toHaveBeenCalledWith("Notification permission denied");
	});

	it("prompts for permission and subscribes once granted", async () => {
		const { NotificationStub, created } = setupPushEnv({
			permission: "default",
			promptResult: "granted",
		});
		expect(await subscribeToPush("BPk")).toBe(created);
		expect(NotificationStub.requestPermission).toHaveBeenCalledOnce();
	});

	it("reuses an existing subscription without subscribing again", async () => {
		const existing = makeSubscription("https://push.example.com/existing");
		const { pushManager } = setupPushEnv({ existing });
		const result = await subscribeToPush("BPk");
		expect(result).toBe(existing);
		expect(pushManager.subscribe).not.toHaveBeenCalled();
	});

	it("subscribes with the decoded applicationServerKey when none exists", async () => {
		const vapidPublicKey = uint8ArrayToUrlBase64(crypto.getRandomValues(new Uint8Array(65)));
		const { pushManager, created } = setupPushEnv({ existing: null });
		const result = await subscribeToPush(vapidPublicKey);

		expect(result).toBe(created);
		expect(pushManager.subscribe).toHaveBeenCalledOnce();
		expect(pushManager.subscribe).toHaveBeenCalledWith({
			userVisibleOnly: true,
			applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
		});
	});
});

describe("unsubscribeFromPush & getCurrentSubscription", () => {
	it("unsubscribe returns true when push is unsupported", async () => {
		setupPushEnv({ serviceWorker: false });
		expect(await unsubscribeFromPush()).toBe(true);
	});

	it("unsubscribe returns true when there is no subscription", async () => {
		setupPushEnv({ existing: null });
		expect(await unsubscribeFromPush()).toBe(true);
	});

	it("unsubscribe calls subscription.unsubscribe when one exists", async () => {
		const existing = makeSubscription();
		setupPushEnv({ existing });
		expect(await unsubscribeFromPush()).toBe(true);
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
	});

	it("unsubscribe returns false when the browser fails to unsubscribe", async () => {
		const existing = makeSubscription();
		existing.unsubscribe.mockResolvedValueOnce(false);
		setupPushEnv({ existing });
		expect(await unsubscribeFromPush()).toBe(false);
	});

	it("getCurrentSubscription returns null when unsupported", async () => {
		setupPushEnv({ serviceWorker: false });
		expect(await getCurrentSubscription()).toBeNull();
	});

	it("getCurrentSubscription returns the current subscription", async () => {
		const existing = makeSubscription();
		setupPushEnv({ existing });
		expect(await getCurrentSubscription()).toBe(existing);
	});

	it("supports the full lifecycle: subscribe, read back, unsubscribe, gone", async () => {
		const { created } = setupPushEnv();
		expect(await getCurrentSubscription()).toBeNull();
		expect(await subscribeToPush("BPk")).toBe(created);
		expect(await getCurrentSubscription()).toBe(created);
		expect(await unsubscribeFromPush()).toBe(true);
		expect(await getCurrentSubscription()).toBeNull();
	});
});

describe("serializeSubscription", () => {
	it("serializes endpoint and base64url-encodes the keys", () => {
		const p256dh = new Uint8Array([1, 2, 3, 4, 5]);
		const auth = new Uint8Array([250, 251, 252]);
		const sub = makeSubscription("https://push.example.com/x", p256dh, auth);

		const out = serializeSubscription(sub);
		expect(out.endpoint).toBe("https://push.example.com/x");
		expect(out.keys.p256dh).toBe(uint8ArrayToUrlBase64(p256dh));
		expect(out.keys.auth).toBe(uint8ArrayToUrlBase64(auth));
	});

	it.each(["p256dh", "auth"])("throws a named error when %s is missing", (missing) => {
		const sub: PushSubscription = {
			...makeSubscription("https://push.example.com/x"),
			getKey: (name) => (name === missing ? null : new Uint8Array([1, 2]).buffer),
		};
		expect(() => serializeSubscription(sub)).toThrow(`Subscription is missing its ${missing} key`);
	});
});

describe("server sync helpers", () => {
	it("sendSubscriptionToServer POSTs the serialized subscription", async () => {
		const mock = stubFetch(200);
		const sub = makeSubscription("https://push.example.com/y");
		const ok = await sendSubscriptionToServer(sub);
		expect(ok).toBe(true);
		expect(mock).toHaveBeenCalledOnce();

		const [url, init] = mock.mock.calls[0];
		expect(url).toBe("/api/push/subscribe");
		expect(init?.method).toBe("POST");
		expect(headersOf(mock)["Content-Type"]).toBe("application/json");
		expect(JSON.parse(init?.body as string)).toEqual(serializeSubscription(sub));
	});

	it("sendSubscriptionToServer rejects when the subscription is missing a key", async () => {
		stubFetch(200);
		const sub: PushSubscription = {
			...makeSubscription(),
			getKey: () => null,
		};
		await expect(sendSubscriptionToServer(sub)).rejects.toThrow(
			"Subscription is missing its p256dh key",
		);
	});

	it("sendSubscriptionToServer propagates a network failure as a rejection", async () => {
		const mock = stubFetch(200);
		mock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
		await expect(sendSubscriptionToServer(makeSubscription())).rejects.toThrow("Failed to fetch");
	});

	it("sendSubscriptionToServer honors a custom endpoint and returns response.ok", async () => {
		const mock = stubFetch(500);
		const sub = makeSubscription();
		const ok = await sendSubscriptionToServer(sub, "/custom");
		expect(ok).toBe(false);
		expect(mock).toHaveBeenCalledOnce();
		expect(mock.mock.calls[0][0]).toBe("/custom");
	});

	it("removeSubscriptionFromServer DELETEs by endpoint", async () => {
		const mock = stubFetch(200);
		const ok = await removeSubscriptionFromServer("https://push.example.com/z");
		expect(ok).toBe(true);
		expect(mock).toHaveBeenCalledOnce();

		const [url, init] = mock.mock.calls[0];
		expect(url).toBe("/api/push/subscribe");
		expect(init?.method).toBe("DELETE");
		expect(JSON.parse(init?.body as string)).toEqual({
			endpoint: "https://push.example.com/z",
		});
	});
});
