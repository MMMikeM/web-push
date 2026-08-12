import { afterEach, describe, expect, it, vi } from "vite-plus/test";
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

type FakeSubscription = {
	endpoint: string;
	unsubscribe: ReturnType<typeof vi.fn>;
	getKey: (name: string) => ArrayBuffer;
};

const makeSubscription = (
	endpoint = "https://push.example.com/sub/1",
	p256dh = new Uint8Array([1, 2, 3, 4]),
	auth = new Uint8Array([9, 8, 7]),
): FakeSubscription => ({
	endpoint,
	unsubscribe: vi.fn(async () => true),
	getKey: (name: string) => (name === "p256dh" ? p256dh.buffer : auth.buffer) as ArrayBuffer,
});

type EnvOptions = {
	supported?: boolean;
	permission?: NotificationPermission;
	existing?: FakeSubscription | null;
	created?: FakeSubscription;
};

/** Stub the browser push globals client.ts reaches for. */
const setupPushEnv = (opts: EnvOptions = {}) => {
	const { supported = true, permission = "granted", existing = null } = opts;
	const created = opts.created ?? makeSubscription("https://push.example.com/sub/new");

	const pushManager = {
		getSubscription: vi.fn(async () => existing),
		subscribe: vi.fn(async (_options?: PushSubscriptionOptionsInit) => created),
	};
	const registration = { pushManager };

	const NotificationStub = {
		permission,
		requestPermission: vi.fn(async () => permission),
	};

	// `in window` / `in navigator` checks drive isPushSupported.
	const windowStub: Record<string, unknown> = { Notification: NotificationStub };
	const navigatorStub: Record<string, unknown> = {};
	if (supported) {
		windowStub.PushManager = function PushManager() {};
		navigatorStub.serviceWorker = { ready: Promise.resolve(registration) };
	}

	vi.stubGlobal("window", windowStub);
	vi.stubGlobal("navigator", navigatorStub);
	vi.stubGlobal("Notification", NotificationStub);

	return { pushManager, registration, created, NotificationStub };
};

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("feature detection & permission", () => {
	it("isPushSupported is true when all APIs are present", () => {
		setupPushEnv({ supported: true });
		expect(isPushSupported()).toBe(true);
	});

	it("isPushSupported is false when serviceWorker/PushManager are missing", () => {
		setupPushEnv({ supported: false });
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
		setupPushEnv({ supported: false });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		expect(await subscribeToPush("BPk")).toBeNull();
		expect(warn).toHaveBeenCalledWith("Push notifications not supported");
	});

	it("returns null and warns when permission is denied", async () => {
		setupPushEnv({ permission: "denied" });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		expect(await subscribeToPush("BPk")).toBeNull();
		expect(warn).toHaveBeenCalledWith("Notification permission denied");
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
		const arg = pushManager.subscribe.mock.calls[0][0] as {
			userVisibleOnly: boolean;
			applicationServerKey: Uint8Array;
		};
		expect(arg.userVisibleOnly).toBe(true);
		expect(new Uint8Array(arg.applicationServerKey)).toEqual(urlBase64ToUint8Array(vapidPublicKey));
	});
});

describe("unsubscribeFromPush & getCurrentSubscription", () => {
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

	it("getCurrentSubscription returns null when unsupported", async () => {
		setupPushEnv({ supported: false });
		expect(await getCurrentSubscription()).toBeNull();
	});

	it("getCurrentSubscription returns the current subscription", async () => {
		const existing = makeSubscription();
		setupPushEnv({ existing });
		expect(await getCurrentSubscription()).toBe(existing);
	});
});

describe("serializeSubscription", () => {
	it("serializes endpoint and base64url-encodes the keys", () => {
		const p256dh = new Uint8Array([1, 2, 3, 4, 5]);
		const auth = new Uint8Array([250, 251, 252]);
		const sub = makeSubscription("https://push.example.com/x", p256dh, auth);

		const out = serializeSubscription(sub as unknown as PushSubscription);
		expect(out.endpoint).toBe("https://push.example.com/x");
		expect(out.keys.p256dh).toBe(uint8ArrayToUrlBase64(p256dh));
		expect(out.keys.auth).toBe(uint8ArrayToUrlBase64(auth));
	});

	it.each(["p256dh", "auth"])("throws a named error when %s is missing", (missing) => {
		const sub = {
			endpoint: "https://push.example.com/x",
			getKey: (name: string) => (name === missing ? null : new Uint8Array([1, 2]).buffer),
		};
		expect(() => serializeSubscription(sub as unknown as PushSubscription)).toThrow(
			new RegExp(`missing its ${missing} key`),
		);
	});
});

describe("server sync helpers", () => {
	const stubFetch = (status = 200) => {
		// Params declared so `mock.calls[0]` is a two-element tuple; see the same
		// note in send.test.ts.
		const mock = vi.fn(
			async (_input: string | URL | Request, _init?: RequestInit) => new Response("", { status }),
		);
		vi.stubGlobal("fetch", mock);
		return mock;
	};

	it("sendSubscriptionToServer POSTs the serialized subscription", async () => {
		const mock = stubFetch(200);
		const sub = makeSubscription("https://push.example.com/y");
		const ok = await sendSubscriptionToServer(sub as unknown as PushSubscription);
		expect(ok).toBe(true);

		const [url, init] = mock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/push/subscribe");
		expect(init.method).toBe("POST");
		expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
		const body = JSON.parse(init.body as string);
		expect(body.endpoint).toBe("https://push.example.com/y");
		expect(body.keys).toHaveProperty("p256dh");
	});

	it("sendSubscriptionToServer honors a custom endpoint and returns response.ok", async () => {
		const mock = stubFetch(500);
		const sub = makeSubscription();
		const ok = await sendSubscriptionToServer(sub as unknown as PushSubscription, "/custom");
		expect(ok).toBe(false);
		expect(mock.mock.calls[0][0]).toBe("/custom");
	});

	it("removeSubscriptionFromServer DELETEs by endpoint", async () => {
		const mock = stubFetch(200);
		const ok = await removeSubscriptionFromServer("https://push.example.com/z");
		expect(ok).toBe(true);

		const [url, init] = mock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/push/subscribe");
		expect(init.method).toBe("DELETE");
		expect(JSON.parse(init.body as string)).toEqual({
			endpoint: "https://push.example.com/z",
		});
	});
});
