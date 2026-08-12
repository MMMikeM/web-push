/**
 * Web Push from a Cloudflare Worker — zero dependencies, Web Crypto only.
 *
 * The `web-push` npm package can't run here: it calls `crypto.createECDH`
 * and `https.request`, neither of which exist in the Workers runtime
 * (see https://github.com/web-push-libs/web-push/issues/718).
 * `@mmmike/web-push` uses only `crypto.subtle` and `fetch`, so it just works.
 *
 * Routes:
 *   GET  /vapid-public-key  -> the public key the browser needs to subscribe
 *   POST /send              -> { subscription, payload } -> sends one push
 */

import { sendPushNotification, WebPushError } from "@mmmike/web-push/send";
import type { PushSubscriptionData, PushPayload } from "@mmmike/web-push";

interface Env {
	VAPID_PUBLIC_KEY: string;
	VAPID_PRIVATE_KEY: string;
	VAPID_SUBJECT: string; // e.g. "mailto:you@example.com"
}

type SendBody = { subscription: PushSubscriptionData; payload: PushPayload };

const json = (data: unknown, status = 200): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === "GET" && url.pathname === "/vapid-public-key") {
			return json({ publicKey: env.VAPID_PUBLIC_KEY });
		}

		if (request.method === "POST" && url.pathname === "/send") {
			try {
				const body = (await request.json()) as SendBody;

				try {
					const delivered = await sendPushNotification(body.subscription, body.payload, {
						publicKey: env.VAPID_PUBLIC_KEY,
						privateKey: env.VAPID_PRIVATE_KEY,
						subject: env.VAPID_SUBJECT,
					});

					// `false` means the subscription is gone (404/410) — delete it from your store.
					return json({ delivered });
				} catch (err) {
					// Forward the push service's status; its 5xx becomes 502 — the fault is upstream.
					if (err instanceof WebPushError) {
						const status = err.statusCode >= 500 ? 502 : err.statusCode;
						return json({ error: err.message }, status);
					}
					// Anything else — invalid VAPID subject/keys, oversized payload, bad
					// topic — means this request was malformed, not the push service.
					return json({ error: (err as Error).message ?? "Unknown error" }, 400);
				}
			} catch {
				return json({ error: "Invalid JSON body" }, 400);
			}
		}

		return json({ error: "Not found" }, 404);
	},
};
