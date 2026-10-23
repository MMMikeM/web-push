import {
	InvalidSubscriptionError,
	isPushServiceEndpoint,
	sendPushNotification,
	WebPushError,
} from "../../src/send.ts";
import type { PushPayload, PushSubscriptionData, VapidConfig } from "../../src/types.ts";

/** The demo's own VAPID pair, set as Worker secrets by `scripts/push-demo-keys.ts`. */
export type DemoEnv = {
	DEMO_VAPID_PUBLIC_KEY?: string;
	DEMO_VAPID_PRIVATE_KEY?: string;
	DEMO_RATE_LIMIT: { limit: (options: { key: string }) => Promise<{ success: boolean }> };
};

const DEMO_PATH = "/demo/push";
const SUBJECT = "https://web-push.thelazyweb.dev";
const MAX_BODY_BYTES = 4096;

// The payload is fixed, so the endpoint can't carry anyone else's message.
const NOTIFICATION: PushPayload = {
	title: "Hello from @mmmike/web-push",
	body: "Sent by this site's Cloudflare Worker, encrypted for this browser alone.",
	url: "/",
	tag: "web-push-demo",
};

const json = (status: number, body: unknown, headers?: HeadersInit): Response =>
	Response.json(body, { status, headers });

/** The posted subscription, or `undefined` when the body isn't one. */
const readSubscription = async (request: Request): Promise<PushSubscriptionData | undefined> => {
	try {
		const { endpoint, keys } = JSON.parse(await request.text()) as Partial<PushSubscriptionData>;
		return typeof endpoint === "string" &&
			isPushServiceEndpoint(endpoint) &&
			typeof keys?.p256dh === "string" &&
			typeof keys.auth === "string"
			? { endpoint, keys: { p256dh: keys.p256dh, auth: keys.auth } }
			: undefined;
	} catch {
		return undefined;
	}
};

// The first wait gives the visitor time to switch away, which the page counts
// down (PushDemo.astro), and Google's push service time to register a
// subscription made moments earlier: it answers 410 until it has (see "Right
// after subscribing" in guides/handle-errors.md). The rest stay shorter than
// the guide's minute, since a visitor is watching.
const RESEND_GAPS_MS = [5000, 2000, 4000, 8000, 16000];

const sendOnce = (subscription: PushSubscriptionData, vapid: VapidConfig): Promise<boolean> =>
	sendPushNotification(subscription, NOTIFICATION, vapid, {
		ttl: 60,
		urgency: "high",
		timeoutMs: 10_000,
	});

const send = async (subscription: PushSubscriptionData, vapid: VapidConfig): Promise<Response> => {
	try {
		for (const gapMs of RESEND_GAPS_MS) {
			await new Promise((resolve) => setTimeout(resolve, gapMs));
			if (await sendOnce(subscription, vapid)) {
				return json(200, { delivered: true });
			}
		}
		return json(410, { error: "The push service says this subscription is gone. Try again." });
	} catch (error) {
		if (error instanceof WebPushError) {
			return json(502, { error: `The push service refused it with a ${error.statusCode}.` });
		}
		if (
			error instanceof TypeError ||
			(error instanceof DOMException && error.name === "TimeoutError")
		) {
			return json(504, { error: "The push service didn't answer." });
		}
		if (error instanceof InvalidSubscriptionError) {
			return json(400, { error: "That subscription isn't valid." });
		}
		// Anything else is this deployment's own fault, such as a bad key pair.
		return json(500, { error: "The demo's own setup is broken." });
	}
};

export const isDemoRequest = (url: URL): boolean => url.pathname === DEMO_PATH;

/**
 * `GET` hands the page the public key to subscribe with; `POST` sends that
 * subscription one fixed notification and keeps nothing.
 */
export const handleDemo = async (request: Request, env: DemoEnv, url: URL): Promise<Response> => {
	const { DEMO_VAPID_PUBLIC_KEY: publicKey, DEMO_VAPID_PRIVATE_KEY: privateKey } = env;
	if (!publicKey || !privateKey) {
		return json(503, { error: "The demo isn't set up on this deployment." });
	}
	if (request.method === "GET") {
		return json(200, { publicKey });
	}
	if (request.method !== "POST") {
		return json(405, { error: "Use GET or POST." }, { Allow: "GET, POST" });
	}
	if (request.headers.get("origin") !== url.origin) {
		return json(403, { error: "Send from this site's demo button." });
	}
	const { success } = await env.DEMO_RATE_LIMIT.limit({
		key: request.headers.get("cf-connecting-ip") ?? "unknown",
	});
	if (!success) {
		return json(429, { error: "That's a lot of test notifications. Try again in a minute." });
	}
	// Checked before reading, so an oversized body is never buffered.
	const declaredBytes = Number(request.headers.get("content-length"));
	if (!declaredBytes || declaredBytes > MAX_BODY_BYTES) {
		return json(413, { error: "Send the subscription alone, as JSON." });
	}
	const subscription = await readSubscription(request);
	if (!subscription) {
		return json(400, { error: "Expected a push subscription from a browser's push service." });
	}
	return send(subscription, { publicKey, privateKey, subject: SUBJECT });
};
