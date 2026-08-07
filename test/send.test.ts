import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { sendPushNotification, WebPushError } from "../src/send";
import type { PushSubscriptionData, VapidConfig } from "../src/types";
import { generateVapidKeys, uint8ArrayToUrlBase64 } from "../src/vapid";
import { type ClientKeys, decodeJwtSegment, decryptAes128gcm, makeClientKeys } from "./helpers";

const ENDPOINT = "https://fcm.googleapis.com/fcm/send/abc123";
const payload = { title: "Hi", body: "There", url: "https://example.com/open" };

let vapid: VapidConfig;
let client: ClientKeys;

beforeAll(async () => {
	const keys = await generateVapidKeys();
	vapid = { ...keys, subject: "mailto:admin@example.com" };
	client = await makeClientKeys();
});

const subscription = (): PushSubscriptionData => ({
	endpoint: ENDPOINT,
	keys: { p256dh: client.p256dh, auth: client.auth },
});

const stubFetch = (status = 201, statusText = "", headers?: Record<string, string>) => {
	// 204/304/1xx must be constructed with a null body or Response throws.
	const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);
	// Params are declared but unused: without them `mock.calls` types as an empty
	// tuple and every `calls[0][1]` below fails to compile.
	const mock = vi.fn(
		async (_input: string | URL | Request, _init?: RequestInit) =>
			new Response(noBody ? null : "err-body", { status, statusText, headers }),
	);
	vi.stubGlobal("fetch", mock);
	return mock;
};

const headersOf = (mock: ReturnType<typeof stubFetch>): Record<string, string> =>
	(mock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;

/** Decode the claims of the `t=` JWT in the `vapid t=…, k=…` Authorization header. */
const vapidClaimsOf = (mock: ReturnType<typeof stubFetch>): { exp: number } =>
	decodeJwtSegment(
		headersOf(mock).Authorization.slice("vapid t=".length).split(", k=")[0].split(".")[1],
	) as { exp: number };

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("sendPushNotification — request shape & encryption", () => {
	it("posts a correctly shaped aes128gcm request", async () => {
		const mock = stubFetch(201);
		const ok = await sendPushNotification(subscription(), payload, vapid);
		expect(ok).toBe(true);
		expect(mock).toHaveBeenCalledOnce();

		const [url, init] = mock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(ENDPOINT);
		expect(init.method).toBe("POST");

		const h = headersOf(mock);
		expect(h["Content-Encoding"]).toBe("aes128gcm");
		expect(h["Content-Type"]).toBe("application/octet-stream");
		expect(h.TTL).toBe("86400");
		expect(h.Authorization).toMatch(/^vapid t=.+, k=.+$/);
		expect(h.Authorization).toContain(`k=${vapid.publicKey}`);
	});

	it("builds the RFC 8188 header (salt | rs=4096 | idlen=65 | keyid)", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);

		const body = new Uint8Array((mock.mock.calls[0][1] as RequestInit).body as ArrayBuffer);
		expect(body.length).toBeGreaterThan(21 + 65);
		const rs = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(16, false);
		expect(rs).toBe(4096);
		expect(body[20]).toBe(65); // keyid length
	});

	it("round-trips the payload: the browser could decrypt it (RFC 8291)", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);

		const body = new Uint8Array((mock.mock.calls[0][1] as RequestInit).body as ArrayBuffer);
		const plaintext = await decryptAes128gcm(body, client);
		expect(new TextDecoder().decode(plaintext)).toBe(JSON.stringify(payload));
	});

	it("uses a fresh salt and ephemeral key on every send", async () => {
		const m1 = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);
		const b1 = new Uint8Array((m1.mock.calls[0][1] as RequestInit).body as ArrayBuffer);
		vi.unstubAllGlobals();
		const m2 = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);
		const b2 = new Uint8Array((m2.mock.calls[0][1] as RequestInit).body as ArrayBuffer);
		expect(b1.slice(0, 16)).not.toEqual(b2.slice(0, 16));
		expect(b1).not.toEqual(b2);
	});
});

describe("sendPushNotification — status handling", () => {
	it.each([200, 201, 204])("returns true on %i", async (status) => {
		stubFetch(status);
		expect(await sendPushNotification(subscription(), payload, vapid)).toBe(true);
	});

	it.each([404, 410])("returns false (dead subscription) on %i", async (status) => {
		stubFetch(status);
		expect(await sendPushNotification(subscription(), payload, vapid)).toBe(false);
	});

	it("throws WebPushError with status/retryAfter on 429", async () => {
		stubFetch(429, "Too Many Requests", { "Retry-After": "120" });
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		expect(err).toBeInstanceOf(WebPushError);
		expect(err).toMatchObject({
			statusCode: 429,
			retryAfter: "120",
			endpoint: ENDPOINT,
			body: "err-body",
		});
		expect(err.message).toMatch(/rate limit/i);
	});

	it("throws WebPushError with the status on other server errors", async () => {
		stubFetch(500, "Internal Server Error");
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		expect(err).toBeInstanceOf(WebPushError);
		expect(err.statusCode).toBe(500);
		expect(err.retryAfter).toBeNull();
		expect(err.message).toMatch(/Push service error: 500/);
	});
});

describe("sendPushNotification — options", () => {
	it("passes a custom ttl to the TTL header", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid, { ttl: 3600 });
		expect(headersOf(mock).TTL).toBe("3600");
	});

	it("logs the response via logger.debug", async () => {
		stubFetch(201);
		const debug = vi.fn();
		await sendPushNotification(subscription(), payload, vapid, { logger: { debug } });
		expect(debug).toHaveBeenCalledWith("Push response", expect.objectContaining({ status: 201 }));
	});

	it("keeps the VAPID JWT expiry within 24h even for a long message ttl", async () => {
		const mock = stubFetch(201);
		const now = Math.floor(Date.now() / 1000);
		await sendPushNotification(subscription(), payload, vapid, { ttl: 30 * 86400 });

		// A JWT exp > 24h from now is rejected (401) by real push services; the
		// TTL header is independent of it.
		expect(vapidClaimsOf(mock).exp).toBeLessThanOrEqual(now + 86400);
		expect(headersOf(mock).TTL).toBe(String(30 * 86400));
	});

	it("honors a custom vapidExpiration", async () => {
		const mock = stubFetch(201);
		const now = Math.floor(Date.now() / 1000);
		await sendPushNotification(subscription(), payload, vapid, { vapidExpiration: 3600 });
		const claims = vapidClaimsOf(mock);
		expect(claims.exp).toBeGreaterThanOrEqual(now + 3600);
		expect(claims.exp).toBeLessThanOrEqual(now + 3600 + 5);
	});

	it("rejects a vapidExpiration over 24 hours", async () => {
		stubFetch(201);
		await expect(
			sendPushNotification(subscription(), payload, vapid, { vapidExpiration: 90000 }),
		).rejects.toThrow(/24 hours/);
	});

	it("sets Urgency and Topic headers when provided", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid, {
			urgency: "high",
			topic: "chat-42",
		});
		const h = headersOf(mock);
		expect(h.Urgency).toBe("high");
		expect(h.Topic).toBe("chat-42");
	});

	it("omits Urgency and Topic headers when not provided", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);
		const h = headersOf(mock);
		expect(h.Urgency).toBeUndefined();
		expect(h.Topic).toBeUndefined();
	});

	it("rejects a topic longer than 32 characters", async () => {
		stubFetch(201);
		await expect(
			sendPushNotification(subscription(), payload, vapid, { topic: "a".repeat(33) }),
		).rejects.toThrow(/Topic/);
	});
});

describe("sendPushNotification — payload size & validation", () => {
	// JSON overhead of {"title":"","body":"..."} with unescaped ASCII body.
	const OVERHEAD = new TextEncoder().encode(JSON.stringify({ title: "", body: "" })).length;

	it("accepts a payload at the single-record limit (3993 plaintext bytes)", async () => {
		stubFetch(201);
		const body = "a".repeat(3993 - OVERHEAD);
		await expect(sendPushNotification(subscription(), { title: "", body }, vapid)).resolves.toBe(
			true,
		);
	});

	it("rejects a payload past the single-record limit", async () => {
		stubFetch(201);
		const body = "a".repeat(3994 - OVERHEAD);
		await expect(sendPushNotification(subscription(), { title: "", body }, vapid)).rejects.toThrow(
			/too large|payload/i,
		);
	});

	it("throws on a malformed endpoint URL", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: "not a url",
			keys: { p256dh: client.p256dh, auth: client.auth },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow();
	});

	it("rejects an invalid p256dh key with a clear error", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: ENDPOINT,
			keys: { p256dh: uint8ArrayToUrlBase64(new Uint8Array(10)), auth: client.auth },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow(/p256dh/);
	});

	it("rejects a too-short auth secret with a clear error", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: ENDPOINT,
			keys: { p256dh: client.p256dh, auth: uint8ArrayToUrlBase64(new Uint8Array(8)) },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow(/auth/);
	});
});
