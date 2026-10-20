import { afterEach, describe, expect, it, Mock, vi } from "vite-plus/test";
import {
	getCurrentSubscription,
	getNotificationPermission,
	isPushSupported,
	removeSubscriptionFromServer,
	requestNotificationPermission,
	sendSubscriptionToServer,
	serializeSubscription,
	subscribe,
	subscribeToPush,
	unsubscribe,
	unsubscribeFromPush,
} from "../src/client";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "../src/vapid";
import { stubFetch } from "./helpers";

// A real PushSubscription, so fakes pass into client.ts without casts; the
// intersection keeps `unsubscribe` a typed mock the tests can assert on.
type FakeSubscription = PushSubscription & {
	unsubscribe: Mock<() => Promise<boolean>>;
};

const makeSubscription = (
	endpoint = "https://push.example.com/sub/1",
	p256dh = new Uint8Array([1, 2, 3, 4]),
	auth = new Uint8Array([9, 8, 7]),
	applicationServerKey: ArrayBuffer | null = null,
): FakeSubscription => ({
	endpoint,
	expirationTime: null,
	options: { applicationServerKey, userVisibleOnly: true },
	unsubscribe: vi.fn<() => Promise<boolean>>(async () => true),
	getKey: (name: PushEncryptionKeyName) => (name === "p256dh" ? p256dh.buffer : auth.buffer),
	toJSON: () => ({ endpoint, expirationTime: null, keys: {} }),
});

type EnvOptions = {
	/** A service worker global: no `navigator.serviceWorker`, no `Notification.requestPermission`. */
	worker?: boolean;
	serviceWorker?: boolean;
	pushManager?: boolean;
	notification?: boolean;
	permission?: NotificationPermission;
	promptResult?: NotificationPermission;
	existing?: FakeSubscription | null;
};

function PushManager() {}

// client.ts touches only `pushManager`; the Pick checks that much of the fake.
const asRegistration = (fake: Pick<ServiceWorkerRegistration, "pushManager">) =>
	fake as ServiceWorkerRegistration;

const setupPushEnv = (opts: EnvOptions = {}) => {
	const {
		worker = false,
		serviceWorker = !worker,
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
		// Chrome rejects `userVisibleOnly: false` here, even in extensions.
		permissionState: vi.fn<(options?: PushSubscriptionOptionsInit) => Promise<PermissionState>>(
			async (options) => {
				if (!options?.userVisibleOnly) {
					throw new DOMException("userVisibleOnly required", "NotSupportedError");
				}
				return "granted";
			},
		),
	};
	const registration = asRegistration({ pushManager });

	const NotificationStub = {
		permission,
		requestPermission: vi.fn<() => Promise<NotificationPermission>>(async () => promptResult),
	};

	// `in globalThis` / `in navigator` checks drive isPushSupported; each flag
	// removes exactly one of its three clauses.
	const navigatorStub: Record<string, unknown> = {};
	if (notification) {
		vi.stubGlobal("Notification", worker ? { permission } : NotificationStub);
	}
	if (hasPushManager) {
		vi.stubGlobal("PushManager", PushManager);
	}
	if (serviceWorker) {
		navigatorStub.serviceWorker = { ready: Promise.resolve(registration) };
	}
	vi.stubGlobal("navigator", navigatorStub);

	return { pushManager, registration, created, NotificationStub };
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

const randomVapidKey = () => uint8ArrayToUrlBase64(crypto.getRandomValues(new Uint8Array(65)));
const subscriptionBoundTo = (vapidPublicKey: string) =>
	makeSubscription(
		"https://push.example.com/existing",
		undefined,
		undefined,
		urlBase64ToUint8Array(vapidPublicKey).buffer,
	);

describe("subscribe", () => {
	it("subscribeToPush is the deprecated alias of subscribe", () => {
		expect(subscribeToPush).toBe(subscribe);
	});

	it("reports unsupported when push APIs are missing", async () => {
		setupPushEnv({ serviceWorker: false });
		expect(await subscribe("BPk")).toEqual({ status: "unsupported" });
	});

	it("reports denied when the permission prompt is declined", async () => {
		setupPushEnv({ permission: "default", promptResult: "denied" });
		expect(await subscribe("BPk")).toEqual({ status: "denied" });
	});

	it("prompts for permission and subscribes once granted", async () => {
		const { NotificationStub, created } = setupPushEnv({
			permission: "default",
			promptResult: "granted",
		});
		expect(await subscribe("BPk")).toEqual({
			status: "subscribed",
			subscription: created,
			isNew: true,
		});
		expect(NotificationStub.requestPermission).toHaveBeenCalledOnce();
	});

	it("reuses an existing subscription bound to the same VAPID key, with isNew false", async () => {
		const vapidPublicKey = randomVapidKey();
		const existing = subscriptionBoundTo(vapidPublicKey);
		const { pushManager } = setupPushEnv({ existing });
		expect(await subscribe(vapidPublicKey)).toEqual({
			status: "subscribed",
			subscription: existing,
			isNew: false,
		});
		expect(pushManager.subscribe).not.toHaveBeenCalled();
	});

	it("keeps an existing subscription whose applicationServerKey the browser does not report", async () => {
		const existing = makeSubscription("https://push.example.com/existing");
		const { pushManager } = setupPushEnv({ existing });
		expect(await subscribe(randomVapidKey())).toEqual({
			status: "subscribed",
			subscription: existing,
			isNew: false,
		});
		expect(existing.unsubscribe).not.toHaveBeenCalled();
		expect(pushManager.subscribe).not.toHaveBeenCalled();
	});

	it("rotates a subscription bound to a different VAPID key and flags it as new", async () => {
		const existing = subscriptionBoundTo(randomVapidKey());
		const { pushManager, created } = setupPushEnv({ existing });
		expect(await subscribe(randomVapidKey())).toEqual({
			status: "subscribed",
			subscription: created,
			isNew: true,
		});
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
		expect(pushManager.subscribe).toHaveBeenCalledOnce();
	});

	it("prompts for permission before waiting on a still-installing service worker", async () => {
		const { NotificationStub } = setupPushEnv({ permission: "default" });
		vi.stubGlobal("navigator", { serviceWorker: { ready: new Promise(() => {}) } });
		void subscribe("BPk");
		await vi.waitFor(() => expect(NotificationStub.requestPermission).toHaveBeenCalledOnce());
	});

	it("replaces a subscription created with a different userVisibleOnly mode", async () => {
		const vapidPublicKey = randomVapidKey();
		const existing = subscriptionBoundTo(vapidPublicKey);
		const { registration, created } = setupPushEnv({ worker: true, existing });
		expect(await subscribe(vapidPublicKey, { registration, userVisibleOnly: false })).toEqual({
			status: "subscribed",
			subscription: created,
			isNew: true,
		});
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
	});

	it("keeps an existing subscription whose userVisibleOnly mode the browser does not report", async () => {
		const vapidPublicKey = randomVapidKey();
		const existing = subscriptionBoundTo(vapidPublicKey);
		Reflect.deleteProperty(existing.options, "userVisibleOnly");
		const { pushManager } = setupPushEnv({ existing });
		expect(await subscribe(vapidPublicKey)).toEqual({
			status: "subscribed",
			subscription: existing,
			isNew: false,
		});
		expect(pushManager.subscribe).not.toHaveBeenCalled();
	});

	it("subscribes with the decoded applicationServerKey when none exists", async () => {
		const vapidPublicKey = randomVapidKey();
		const { pushManager, created } = setupPushEnv({ existing: null });
		const result = await subscribe(vapidPublicKey);

		expect(result).toEqual({ status: "subscribed", subscription: created, isNew: true });
		expect(pushManager.subscribe).toHaveBeenCalledOnce();
		expect(pushManager.subscribe).toHaveBeenCalledWith({
			userVisibleOnly: true,
			applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
		});
	});
});

describe("from a service worker", () => {
	it("subscribes on the given registration with userVisibleOnly false, without prompting", async () => {
		const vapidPublicKey = randomVapidKey();
		const { registration, pushManager, created } = setupPushEnv({ worker: true });

		expect(await subscribe(vapidPublicKey, { registration, userVisibleOnly: false })).toEqual({
			status: "subscribed",
			subscription: created,
			isNew: true,
		});
		expect(pushManager.subscribe).toHaveBeenCalledWith({
			userVisibleOnly: false,
			applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
		});
	});

	it.each(["default", "denied"] as const)(
		"reports denied when the notification permission is %s",
		async (permission) => {
			const { registration, pushManager } = setupPushEnv({ worker: true, permission });
			expect(await subscribe("BPk", { registration })).toEqual({ status: "denied" });
			expect(pushManager.subscribe).not.toHaveBeenCalled();
		},
	);

	it("reports unsupported when PushManager is missing, even with a registration", async () => {
		const { registration } = setupPushEnv({ worker: true, pushManager: false });
		expect(await subscribe("BPk", { registration })).toEqual({ status: "unsupported" });
	});

	it("reads and unsubscribes through the given registration", async () => {
		const existing = makeSubscription();
		const { registration } = setupPushEnv({ worker: true, existing });
		expect(await getCurrentSubscription({ registration })).toBe(existing);
		expect(await unsubscribe({ registration })).toBe(existing.endpoint);
		expect(await getCurrentSubscription({ registration })).toBeNull();
	});
});

describe("unsubscribe & getCurrentSubscription", () => {
	it("unsubscribeFromPush returns true when push is unsupported", async () => {
		setupPushEnv({ serviceWorker: false });
		expect(await unsubscribeFromPush()).toBe(true);
	});

	it("unsubscribeFromPush returns true when there is no subscription", async () => {
		setupPushEnv({ existing: null });
		expect(await unsubscribeFromPush()).toBe(true);
	});

	it("unsubscribeFromPush calls subscription.unsubscribe when one exists", async () => {
		const existing = makeSubscription();
		setupPushEnv({ existing });
		expect(await unsubscribeFromPush()).toBe(true);
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
	});

	it("unsubscribeFromPush returns false when the browser fails to unsubscribe", async () => {
		const existing = makeSubscription();
		existing.unsubscribe.mockResolvedValueOnce(false);
		setupPushEnv({ existing });
		expect(await unsubscribeFromPush()).toBe(false);
	});

	it("unsubscribe returns null when push is unsupported", async () => {
		setupPushEnv({ serviceWorker: false });
		expect(await unsubscribe()).toBeNull();
	});

	it("unsubscribe returns null when there is no subscription", async () => {
		setupPushEnv({ existing: null });
		expect(await unsubscribe()).toBeNull();
	});

	it("unsubscribe calls subscription.unsubscribe and returns its endpoint", async () => {
		const existing = makeSubscription();
		setupPushEnv({ existing });
		expect(await unsubscribe()).toBe(existing.endpoint);
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
	});

	it("unsubscribe still returns the endpoint when the browser reports failure", async () => {
		const existing = makeSubscription();
		existing.unsubscribe.mockResolvedValueOnce(false);
		setupPushEnv({ existing });
		expect(await unsubscribe()).toBe(existing.endpoint);
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
	});

	it("unsubscribe still returns the endpoint when the browser rejects the unsubscribe", async () => {
		const existing = makeSubscription();
		existing.unsubscribe.mockRejectedValueOnce(new Error("push service unreachable"));
		setupPushEnv({ existing });
		expect(await unsubscribe()).toBe(existing.endpoint);
		expect(existing.unsubscribe).toHaveBeenCalledOnce();
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
		expect(await subscribe("BPk")).toEqual({
			status: "subscribed",
			subscription: created,
			isNew: true,
		});
		expect(await getCurrentSubscription()).toBe(created);
		expect(await unsubscribe()).toBe(created.endpoint);
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
		expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
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

	it("sendSubscriptionToServer merges init headers with the JSON content type", async () => {
		const mock = stubFetch(200);
		const controller = new AbortController();
		await sendSubscriptionToServer(makeSubscription(), "https://api.example.com/push", {
			headers: { Authorization: "Bearer t0k" },
			credentials: "include",
			signal: controller.signal,
		});

		const [url, init] = mock.mock.calls[0];
		const headers = new Headers(init?.headers);
		expect(url).toBe("https://api.example.com/push");
		expect(init?.method).toBe("POST");
		expect(init?.credentials).toBe("include");
		expect(init?.signal).toBe(controller.signal);
		expect(headers.get("Authorization")).toBe("Bearer t0k");
		expect(headers.get("Content-Type")).toBe("application/json");
	});

	it.each([
		{ form: "a Headers instance", headers: new Headers({ Authorization: "Bearer t0k" }) },
		{ form: "an entry array", headers: [["Authorization", "Bearer t0k"]] satisfies HeadersInit },
	])("sendSubscriptionToServer accepts init headers as $form", async ({ headers }) => {
		const mock = stubFetch(200);
		await sendSubscriptionToServer(makeSubscription(), undefined, { headers });
		const sent = new Headers(mock.mock.calls[0][1]?.headers);
		expect(sent.get("Authorization")).toBe("Bearer t0k");
		expect(sent.get("Content-Type")).toBe("application/json");
	});

	it("sendSubscriptionToServer keeps a Content-Type the caller sets", async () => {
		const mock = stubFetch(200);
		await sendSubscriptionToServer(makeSubscription(), undefined, {
			headers: { "content-type": "application/json; charset=utf-8" },
		});
		expect(new Headers(mock.mock.calls[0][1]?.headers).get("Content-Type")).toBe(
			"application/json; charset=utf-8",
		);
	});

	it("sendSubscriptionToServer always sends the serialized subscription as the body", async () => {
		const mock = stubFetch(200);
		const sub = makeSubscription();
		// @ts-expect-error the body is the library's to set
		await sendSubscriptionToServer(sub, undefined, { body: "replaced" });
		expect(JSON.parse(mock.mock.calls[0][1]?.body as string)).toEqual(serializeSubscription(sub));
	});

	it("removeSubscriptionFromServer takes its method and headers from init", async () => {
		const mock = stubFetch(200);
		await removeSubscriptionFromServer("https://push.example.com/z", "/api/push/unsubscribe", {
			method: "POST",
			headers: { Authorization: "Bearer t0k" },
		});

		const [url, init] = mock.mock.calls[0];
		expect(url).toBe("/api/push/unsubscribe");
		expect(init?.method).toBe("POST");
		expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer t0k");
		expect(JSON.parse(init?.body as string)).toEqual({ endpoint: "https://push.example.com/z" });
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
