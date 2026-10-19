import { afterEach, beforeAll, describe, expect, it, vi } from "vite-plus/test";
import { rawPayload, sendPushBatch, WebPushError } from "../src/send";
import type { PushSubscriptionData, VapidConfig } from "../src/types";
import { generateVapidKeys, uint8ArrayToUrlBase64 } from "../src/vapid";
import { type ClientKeys, decodeJwtSegment, makeClientKeys, stubFetch } from "./helpers";

const payload = { title: "Hi", body: "There" };

let vapid: VapidConfig;
let client: ClientKeys;

beforeAll(async () => {
	const keys = await generateVapidKeys();
	vapid = { ...keys, subject: "mailto:admin@example.com" };
	client = await makeClientKeys();
});

const subscription = (endpoint: string): PushSubscriptionData => ({
	endpoint,
	keys: { p256dh: client.p256dh, auth: client.auth },
});

/** Stub `fetch` per endpoint; endpoints missing from the map answer 201. */
const stubFetchByEndpoint = (
	statusByEndpoint: Record<string, number>,
): ReturnType<typeof stubFetch> => {
	const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
		async (input) => new Response("err-body", { status: statusByEndpoint[String(input)] ?? 201 }),
	);
	vi.stubGlobal("fetch", mock);
	return mock;
};

const authHeaderOf = (call: [string | URL | Request, RequestInit?]): string =>
	((call[1] as RequestInit).headers as Record<string, string>).Authorization;

afterEach(() => {
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

describe("sendPushBatch — result partitioning", () => {
	it("splits results: delivered in neither list, 404/410 in gone, rejections in failed", async () => {
		stubFetchByEndpoint({
			"https://push.example/ok": 201,
			"https://push.example/gone": 410,
			"https://push.example/missing": 404,
			"https://push.example/limited": 429,
		});
		const { delivered, gone, failed } = await sendPushBatch(
			["ok", "gone", "missing", "limited"].map((path) =>
				subscription(`https://push.example/${path}`),
			),
			payload,
			vapid,
		);

		expect(delivered).toBe(1);
		expect(gone.toSorted()).toEqual(["https://push.example/gone", "https://push.example/missing"]);
		expect(failed).toHaveLength(1);
		expect(failed[0].endpoint).toBe("https://push.example/limited");
		expect(failed[0].error).toBeInstanceOf(WebPushError);
		expect((failed[0].error as WebPushError).statusCode).toBe(429);
	});

	it("keeps a WebPushError's retryAfter reachable through failed, raw and parsed", async () => {
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async () => new Response("err-body", { status: 429, headers: { "Retry-After": "120" } }),
		);
		vi.stubGlobal("fetch", mock);

		const { failed } = await sendPushBatch(
			[subscription("https://push.example/a")],
			payload,
			vapid,
		);
		expect((failed[0].error as WebPushError).retryAfter).toBe("120");
		expect((failed[0].error as WebPushError).retryAfterMs).toBe(120000);
	});

	it("puts network failures in failed without stopping the rest of the batch", async () => {
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async (input) => {
				if (String(input).endsWith("/dead")) {
					throw new TypeError("fetch failed");
				}
				return new Response("", { status: 201 });
			},
		);
		vi.stubGlobal("fetch", mock);

		const { delivered, gone, failed } = await sendPushBatch(
			[subscription("https://push.example/dead"), subscription("https://push.example/ok")],
			payload,
			vapid,
		);

		expect(delivered).toBe(1);
		expect(gone).toEqual([]);
		expect(failed).toHaveLength(1);
		expect(failed[0]).toMatchObject({ endpoint: "https://push.example/dead" });
		expect(failed[0].error).toBeInstanceOf(TypeError);
		expect(mock).toHaveBeenCalledTimes(2);
	});

	it("puts a subscription with malformed keys in failed without fetching it", async () => {
		const mock = stubFetch(201);
		const bad: PushSubscriptionData = {
			endpoint: "https://push.example/bad-keys",
			keys: { p256dh: uint8ArrayToUrlBase64(new Uint8Array(10)), auth: client.auth },
		};

		const { failed } = await sendPushBatch(
			[bad, subscription("https://push.example/ok")],
			payload,
			vapid,
		);

		expect(failed).toHaveLength(1);
		expect(failed[0].endpoint).toBe("https://push.example/bad-keys");
		expect((failed[0].error as Error).message).toMatch(/Invalid subscription p256dh key/);
		expect(mock).toHaveBeenCalledTimes(1);
		expect(mock.mock.calls[0][0]).toBe("https://push.example/ok");
	});

	it("puts a non-https endpoint in failed without fetching it", async () => {
		const mock = stubFetch(201);

		const { delivered, failed } = await sendPushBatch(
			[subscription("http://push.example/insecure"), subscription("https://push.example/ok")],
			payload,
			vapid,
		);

		expect(delivered).toBe(1);
		expect(failed).toHaveLength(1);
		expect(failed[0].endpoint).toBe("http://push.example/insecure");
		expect((failed[0].error as Error).message).toMatch(/must be an https: URL/);
		expect(mock).toHaveBeenCalledTimes(1);
		expect(mock.mock.calls[0][0]).toBe("https://push.example/ok");
	});

	it("puts a null row in failed instead of rejecting the whole batch", async () => {
		stubFetch(201);
		const rows: PushSubscriptionData[] = JSON.parse(
			JSON.stringify([
				subscription("https://push.example/a"),
				null,
				subscription("https://push.example/b"),
			]),
		);

		const result = await sendPushBatch(rows, payload, vapid);

		expect(result.delivered).toBe(2);
		expect(result.failed).toEqual([{ endpoint: "", error: expect.any(TypeError) }]);
	});

	it("delivers a rawPayload-wrapped payload", async () => {
		const mock = stubFetch(201);
		const { delivered } = await sendPushBatch(
			[subscription("https://push.example/a")],
			rawPayload('{"custom":"shape"}'),
			vapid,
		);
		expect(delivered).toBe(1);
		expect(mock).toHaveBeenCalledOnce();
	});

	it("resolves to an all-empty result for an empty subscription array without fetching", async () => {
		const mock = stubFetch(201);
		await expect(sendPushBatch([], payload, vapid)).resolves.toEqual({
			delivered: 0,
			gone: [],
			failed: [],
		});
		expect(mock).not.toHaveBeenCalled();
	});
});

describe("sendPushBatch — VAPID JWT reuse", () => {
	it("reuses one JWT across sends to the same push-service origin", async () => {
		const mock = stubFetch(201);
		await sendPushBatch(
			[1, 2, 3].map((i) => subscription(`https://push.example/sub-${i}`)),
			payload,
			vapid,
		);

		// ES256 signatures are randomized, so three identical tokens can only
		// mean one signature was shared — not three signs of the same claims.
		const tokens = new Set(mock.mock.calls.map(authHeaderOf));
		expect(mock).toHaveBeenCalledTimes(3);
		expect(tokens.size).toBe(1);
	});

	it("signs a separate JWT per origin, with the aud claim of each", async () => {
		const mock = stubFetch(201);
		await sendPushBatch(
			[
				subscription("https://fcm.googleapis.com/fcm/send/1"),
				subscription("https://updates.push.services.mozilla.com/wpush/v2/2"),
				subscription("https://fcm.googleapis.com/fcm/send/3"),
			],
			payload,
			vapid,
		);

		const audienceFor = (endpoint: string): string => {
			const call = mock.mock.calls.find((c) => String(c[0]) === endpoint);
			if (!call) {
				throw new Error(`no fetch call for ${endpoint}`);
			}
			const jwt = authHeaderOf(call).slice("vapid t=".length).split(", k=")[0];
			return (decodeJwtSegment(jwt.split(".")[1]) as { aud: string }).aud;
		};

		expect(audienceFor("https://fcm.googleapis.com/fcm/send/1")).toBe("https://fcm.googleapis.com");
		expect(audienceFor("https://updates.push.services.mozilla.com/wpush/v2/2")).toBe(
			"https://updates.push.services.mozilla.com",
		);
		expect(new Set(mock.mock.calls.map(authHeaderOf)).size).toBe(2);
	});

	it("never sends an expired JWT, even when the batch outlasts vapidExpiration", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const sends: { sentAt: number; exp: number }[] = [];
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async (_input, init) => {
				const jwt = ((init as RequestInit).headers as Record<string, string>).Authorization.slice(
					"vapid t=".length,
				).split(", k=")[0];
				const { exp } = decodeJwtSegment(jwt.split(".")[1]) as { exp: number };
				sends.push({ sentAt: Date.now(), exp: exp * 1000 });
				vi.setSystemTime(Date.now() + 31_000);
				return new Response(null, { status: 201 });
			},
		);
		vi.stubGlobal("fetch", mock);

		await sendPushBatch(
			[1, 2, 3].map((i) => subscription(`https://push.example/sub-${i}`)),
			payload,
			vapid,
			{ vapidExpiration: 60, concurrency: 1 },
		);

		expect(sends).toHaveLength(3);
		for (const { sentAt, exp } of sends) {
			expect(exp).toBeGreaterThan(sentAt);
		}
	});
});

describe("sendPushBatch — concurrency", () => {
	it("never has more sends in flight than the concurrency bound", async () => {
		let inFlight = 0;
		let maxInFlight = 0;
		const gates: Array<() => void> = [];
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async () => {
				inFlight += 1;
				maxInFlight = Math.max(maxInFlight, inFlight);
				await new Promise<void>((resolve) => gates.push(resolve));
				inFlight -= 1;
				return new Response("", { status: 201 });
			},
		);
		vi.stubGlobal("fetch", mock);

		const pending = sendPushBatch(
			[1, 2, 3, 4, 5].map((i) => subscription(`https://push.example/sub-${i}`)),
			payload,
			vapid,
			{ concurrency: 2 },
		);

		// Both workers must arrive without any release; a third would be a leak.
		await vi.waitFor(() => expect(gates.length).toBe(2));
		expect(mock).toHaveBeenCalledTimes(2);

		let released = 0;
		while (released < 5) {
			// oxlint-disable-next-line no-await-in-loop -- releases are sequential on purpose: one gate opens one slot
			await vi.waitFor(() => expect(gates.length).toBeGreaterThan(0));
			gates.shift()?.();
			released += 1;
		}

		const result = await pending;
		expect(result.delivered).toBe(5);
		expect(maxInFlight).toBe(2);
		expect(mock).toHaveBeenCalledTimes(5);
	});

	it("stops starting new sends once the caller's signal aborts", async () => {
		const controller = new AbortController();
		const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
			async () => {
				controller.abort();
				return new Response("", { status: 201 });
			},
		);
		vi.stubGlobal("fetch", mock);

		const { delivered, gone, failed } = await sendPushBatch(
			[1, 2, 3, 4, 5].map((i) => subscription(`https://push.example/sub-${i}`)),
			payload,
			vapid,
			{ concurrency: 2, signal: controller.signal },
		);

		// Both workers had already claimed a subscription; nobody claims a third.
		expect(mock).toHaveBeenCalledTimes(2);
		expect(delivered).toBe(2);
		expect(gone).toEqual([]);
		expect(failed).toEqual([]);
	});

	it.each([0, -1, 1.5])("rejects a concurrency of %s before sending anything", async (bad) => {
		const mock = stubFetch(201);
		await expect(
			sendPushBatch([subscription("https://push.example/a")], payload, vapid, { concurrency: bad }),
		).rejects.toThrow("concurrency must be a positive integer");
		expect(mock).not.toHaveBeenCalled();
	});
});

describe("sendPushBatch — caller input rejects up front", () => {
	it.each([
		[
			"a VAPID subject that is not a contact URI",
			{ subject: "admin@example.com" },
			"VAPID subject must be a 'mailto:' or 'https://' URI",
		],
		[
			"a truncated VAPID public key",
			{ publicKey: "AAAA" },
			"VAPID public key must be a 65-byte uncompressed P-256 point",
		],
	])("throws on %s before any send", async (_name, override, message) => {
		const mock = stubFetch(201);
		await expect(
			sendPushBatch([subscription("https://push.example/a")], payload, { ...vapid, ...override }),
		).rejects.toThrow(message);
		expect(mock).not.toHaveBeenCalled();
	});

	it("throws on an oversized payload once, not once per subscription", async () => {
		const mock = stubFetch(201);
		const subs = [1, 2, 3].map((i) => subscription(`https://push.example/sub-${i}`));
		await expect(sendPushBatch(subs, { title: "", body: "a".repeat(4000) }, vapid)).rejects.toThrow(
			/^Payload too large/,
		);
		expect(mock).not.toHaveBeenCalled();
	});

	it("throws on an invalid topic before any send", async () => {
		const mock = stubFetch(201);
		await expect(
			sendPushBatch([subscription("https://push.example/a")], payload, vapid, { topic: "a+b" }),
		).rejects.toThrow("Topic must be 1-32 URL-safe base64 characters");
		expect(mock).not.toHaveBeenCalled();
	});

	it("throws on a timeoutMs AbortSignal.timeout would mishandle before any send", async () => {
		const mock = stubFetch(201);
		await expect(
			sendPushBatch([subscription("https://push.example/a")], payload, vapid, { timeoutMs: 3e9 }),
		).rejects.toThrow("timeoutMs must be a whole number of milliseconds from 1 to 2147483647");
		expect(mock).not.toHaveBeenCalled();
	});

	it("throws on an invalid ttl once, not once per subscription", async () => {
		const mock = stubFetch(201);
		const subs = [1, 2, 3].map((i) => subscription(`https://push.example/sub-${i}`));
		await expect(sendPushBatch(subs, payload, vapid, { ttl: -1 })).rejects.toThrow(
			"ttl must be a whole number of seconds, 0 or more",
		);
		expect(mock).not.toHaveBeenCalled();
	});

	it("throws on a NaN vapidExpiration once, instead of signing exp: null", async () => {
		const mock = stubFetch(201);
		await expect(
			sendPushBatch([subscription("https://push.example/a")], payload, vapid, {
				vapidExpiration: Number.NaN,
			}),
		).rejects.toThrow("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");
		expect(mock).not.toHaveBeenCalled();
	});
});

describe("sendPushBatch — options pass-through", () => {
	it("applies ttl, urgency, and topic to every send in the batch", async () => {
		const mock = stubFetch(201);
		await sendPushBatch(
			[subscription("https://push.example/a"), subscription("https://push.example/b")],
			payload,
			vapid,
			{ ttl: 3600, urgency: "high", topic: "chat-42" },
		);

		for (const call of mock.mock.calls) {
			const headers = (call[1] as RequestInit).headers as Record<string, string>;
			expect(headers.TTL).toBe("3600");
			expect(headers.Urgency).toBe("high");
			expect(headers.Topic).toBe("chat-42");
		}
	});
});
