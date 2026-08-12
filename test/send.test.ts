import { afterEach, beforeAll, describe, expect, it, vi } from "vite-plus/test";
import { encryptPayload } from "../src/encrypt";
import { sendPushNotification, WebPushError } from "../src/send";
import type { PushSubscriptionData, VapidConfig } from "../src/types";
import { generateVapidKeys, uint8ArrayToUrlBase64 } from "../src/vapid";
import {
	type ClientKeys,
	decodeJwtSegment,
	decryptAes128gcm,
	headersOf,
	makeClientKeys,
	stubFetch,
	verifyJwtSignature,
} from "./helpers";

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

/** The `t=` JWT of the `vapid t=…, k=…` Authorization header. */
const vapidJwtOf = (mock: ReturnType<typeof stubFetch>): string =>
	headersOf(mock).Authorization.slice("vapid t=".length).split(", k=")[0];

const vapidClaimsOf = (mock: ReturnType<typeof stubFetch>): { aud: string; exp: number } =>
	decodeJwtSegment(vapidJwtOf(mock).split(".")[1]) as { aud: string; exp: number };

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("sendPushNotification — request shape & encryption", () => {
	it("posts a correctly shaped aes128gcm request", async () => {
		const mock = stubFetch(201);
		const ok = await sendPushNotification(subscription(), payload, vapid);
		expect(ok).toBe(true);
		expect(mock).toHaveBeenCalledOnce();

		const [url, init] = mock.mock.calls[0];
		expect(url).toBe(ENDPOINT);
		expect(init?.method).toBe("POST");

		const h = headersOf(mock);
		expect(h["Content-Encoding"]).toBe("aes128gcm");
		expect(h["Content-Type"]).toBe("application/octet-stream");
		expect(h.TTL).toBe("86400");
		expect(h.Authorization).toMatch(/^vapid t=.+, k=.+$/);
		expect(h.Authorization).toContain(`k=${vapid.publicKey}`);
		expect(await verifyJwtSignature(vapidJwtOf(mock), vapid.publicKey)).toBe(true);
	});

	it("signs the VAPID aud claim as the push service origin, not the full endpoint", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);
		expect(vapidClaimsOf(mock).aud).toBe("https://fcm.googleapis.com");
	});

	it("builds the RFC 8188 header (salt | rs=4096 | idlen=65 | keyid)", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);

		const body = new Uint8Array((mock.mock.calls[0][1] as RequestInit).body as ArrayBuffer);
		expect(body.length).toBeGreaterThan(21 + 65);
		const rs = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(16, false);
		expect(rs).toBe(4096);
		expect(body[20]).toBe(65);
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
			retryAfterMs: 120000,
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
		expect(err.retryAfterMs).toBeNull();
		expect(err.message).toMatch(/Push service error: 500/);
	});

	it("carries Retry-After through on non-429 errors too", async () => {
		stubFetch(503, "Service Unavailable", { "Retry-After": "30" });
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		expect(err).toBeInstanceOf(WebPushError);
		expect(err).toMatchObject({ statusCode: 503, retryAfter: "30", retryAfterMs: 30000 });
	});

	it("parses an HTTP-date Retry-After into milliseconds from now", async () => {
		stubFetch(503, "Service Unavailable", {
			"Retry-After": new Date(Date.now() + 60000).toUTCString(),
		});
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		// toUTCString drops sub-second precision, so allow up to a second of slack.
		expect(err.retryAfterMs).toBeGreaterThan(55000);
		expect(err.retryAfterMs).toBeLessThanOrEqual(60000);
	});

	it("clamps an HTTP-date Retry-After in the past to zero", async () => {
		stubFetch(503, "Service Unavailable", {
			"Retry-After": new Date(Date.now() - 60000).toUTCString(),
		});
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		expect(err.retryAfterMs).toBe(0);
	});

	it("keeps the raw header but a null retryAfterMs when Retry-After is unparseable", async () => {
		stubFetch(429, "Too Many Requests", { "Retry-After": "soonish" });
		const err = await sendPushNotification(subscription(), payload, vapid).catch((e) => e);
		expect(err.retryAfter).toBe("soonish");
		expect(err.retryAfterMs).toBeNull();
	});
});

describe("sendPushNotification — abort & timeout", () => {
	it("attaches an abort signal with the default timeout to every request", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid);
		const init = mock.mock.calls[0][1] as RequestInit;
		expect(init.signal).toBeInstanceOf(AbortSignal);
		expect(init.signal?.aborted).toBe(false);
	});

	it("rejects when the caller's signal is already aborted", async () => {
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async (_input, init) => {
				if (init?.signal?.aborted) {
					throw new DOMException("This operation was aborted", "AbortError");
				}
				return new Response("", { status: 201 });
			},
		);
		vi.stubGlobal("fetch", mock);

		const controller = new AbortController();
		controller.abort();
		await expect(
			sendPushNotification(subscription(), payload, vapid, { signal: controller.signal }),
		).rejects.toThrow(/aborted/i);
	});

	it("rejects a non-positive timeoutMs before sending", async () => {
		const mock = stubFetch(201);
		await expect(
			sendPushNotification(subscription(), payload, vapid, { timeoutMs: 0 }),
		).rejects.toThrow("timeoutMs must be a positive number of milliseconds");
		expect(mock).not.toHaveBeenCalled();
	});
});

describe("sendPushNotification — options", () => {
	it("passes a custom ttl to the TTL header", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid, { ttl: 3600 });
		expect(headersOf(mock).TTL).toBe("3600");
	});

	it("passes ttl 0 (deliver-now-or-drop, RFC 8030 §5.2) through as TTL: 0", async () => {
		const mock = stubFetch(201);
		await sendPushNotification(subscription(), payload, vapid, { ttl: 0 });
		expect(headersOf(mock).TTL).toBe("0");
	});

	it("logs the response via logger.debug", async () => {
		stubFetch(201);
		const debug = vi.fn<(message: string, data?: Record<string, unknown>) => void>();
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
		const before = Math.floor(Date.now() / 1000);
		await sendPushNotification(subscription(), payload, vapid, { vapidExpiration: 3600 });
		const after = Math.floor(Date.now() / 1000);
		const claims = vapidClaimsOf(mock);
		expect(claims.exp).toBeGreaterThanOrEqual(before + 3600);
		expect(claims.exp).toBeLessThanOrEqual(after + 3600);
	});

	it("rejects a vapidExpiration over 24 hours", async () => {
		stubFetch(201);
		await expect(
			sendPushNotification(subscription(), payload, vapid, { vapidExpiration: 90000 }),
		).rejects.toThrow("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");
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
		).rejects.toThrow("Topic must be 1-32 URL-safe base64 characters");
	});

	it("accepts a topic at the 32-character limit", async () => {
		const mock = stubFetch(201);
		const topic = "a".repeat(32);
		await sendPushNotification(subscription(), payload, vapid, { topic });
		expect(headersOf(mock).Topic).toBe(topic);
	});

	it("rejects a topic with characters outside URL-safe base64", async () => {
		stubFetch(201);
		await expect(
			sendPushNotification(subscription(), payload, vapid, { topic: "a+b" }),
		).rejects.toThrow("Topic must be 1-32 URL-safe base64 characters");
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

	it("measures the limit in UTF-8 bytes, not characters", async () => {
		stubFetch(201);
		const emoji = "🍉".repeat(100); // 100 characters, 400 UTF-8 bytes
		const room = 3993 - OVERHEAD - new TextEncoder().encode(emoji).length;
		const body = emoji + "a".repeat(room);
		await expect(sendPushNotification(subscription(), { title: "", body }, vapid)).resolves.toBe(
			true,
		);
		await expect(
			sendPushNotification(subscription(), { title: "", body: `${body}a` }, vapid),
		).rejects.toThrow(/^Payload too large/);
	});

	it("rejects a payload past the single-record limit", async () => {
		stubFetch(201);
		const body = "a".repeat(3994 - OVERHEAD);
		await expect(sendPushNotification(subscription(), { title: "", body }, vapid)).rejects.toThrow(
			/^Payload too large: \d+ bytes exceeds the 3993-byte single-record limit$/,
		);
	});

	it("throws on a malformed endpoint URL", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: "not a url",
			keys: { p256dh: client.p256dh, auth: client.auth },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow("Invalid URL");
	});

	it("rejects an invalid p256dh key with a clear error", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: ENDPOINT,
			keys: { p256dh: uint8ArrayToUrlBase64(new Uint8Array(10)), auth: client.auth },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow(
			"Invalid subscription p256dh key: expected a 65-byte uncompressed P-256 public key",
		);
	});

	it("rejects a too-short auth secret with a clear error", async () => {
		stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: ENDPOINT,
			keys: { p256dh: client.p256dh, auth: uint8ArrayToUrlBase64(new Uint8Array(8)) },
		};
		await expect(sendPushNotification(bad, payload, vapid)).rejects.toThrow(
			"Invalid subscription auth secret: expected at least 16 bytes",
		);
	});
});

describe("encryptPayload — round-trip across payload sizes", () => {
	// 0 and 1 pin the padding delimiter, 3992/3993 the single-record boundary;
	// random binary bytes rule out any ASCII/JSON assumption in the record path.
	it.each([0, 1, 1337, 3992, 3993])("round-trips a %i-byte random payload", async (size) => {
		const plaintext = crypto.getRandomValues(new Uint8Array(size));
		const body = await encryptPayload(plaintext, client.p256dh, client.auth);
		expect(await decryptAes128gcm(body, client)).toEqual(plaintext);
	});
});
