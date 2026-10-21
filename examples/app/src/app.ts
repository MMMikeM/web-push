import type {
	PushPayload,
	PushSubscriptionData,
	VapidConfig,
} from "@mmmike/web-push";
import { sendPushBatch } from "@mmmike/web-push/send";
import type { SubscriptionStore } from "./store.ts";

export type AppConfig = {
	vapid: VapidConfig;
	/** Guards the broadcast route, which pushes to every subscriber */
	adminToken: string;
	store: SubscriptionStore;
};

// The send functions POST to whatever endpoint a subscription names, and
// subscriptions come from browsers, so only accept the real push services.
const PUSH_SERVICE_HOSTS = [
	/^fcm\.googleapis\.com$/,
	/\.notify\.windows\.com$/,
	/\.push\.services\.mozilla\.com$/,
	/\.push\.apple\.com$/,
];

const isPushServiceEndpoint = (endpoint: string): boolean => {
	try {
		const { protocol, hostname } = new URL(endpoint);
		return (
			protocol === "https:" &&
			PUSH_SERVICE_HOSTS.some((host) => host.test(hostname))
		);
	} catch {
		return false;
	}
};

const isSubscription = (value: unknown): value is PushSubscriptionData => {
	const candidate = value as Partial<PushSubscriptionData> | null;
	return (
		typeof candidate?.endpoint === "string" &&
		typeof candidate.keys?.p256dh === "string" &&
		typeof candidate.keys.auth === "string"
	);
};

const isPayload = (value: unknown): value is PushPayload =>
	typeof (value as Partial<PushPayload> | null)?.title === "string";

const json = (data: unknown, status = 200): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});

const readJson = async (request: Request): Promise<unknown> => {
	try {
		return await request.json();
	} catch {
		return undefined;
	}
};

/**
 * The whole server as one fetch handler, so the Node and Workers entry points
 * only have to supply storage, secrets, and a way to serve it.
 */
export const createApp = ({ vapid, adminToken, store }: AppConfig) => {
	const saveSubscription = async (request: Request): Promise<Response> => {
		const subscription = await readJson(request);
		if (
			!isSubscription(subscription) ||
			!isPushServiceEndpoint(subscription.endpoint)
		) {
			return json(
				{ error: "Expected a subscription from a known push service" },
				400,
			);
		}
		await store.put(subscription);
		return json({ saved: true });
	};

	const deleteSubscription = async (request: Request): Promise<Response> => {
		const body = (await readJson(request)) as
			| { endpoint?: unknown }
			| undefined;
		if (typeof body?.endpoint !== "string") {
			return json({ error: "Expected { endpoint }" }, 400);
		}
		await store.delete(body.endpoint);
		return json({ deleted: true });
	};

	const broadcast = async (request: Request): Promise<Response> => {
		if (request.headers.get("authorization") !== `Bearer ${adminToken}`) {
			return json({ error: "Unauthorized" }, 401);
		}
		const payload = await readJson(request);
		if (!isPayload(payload)) {
			return json({ error: "Expected a payload with a title" }, 400);
		}
		try {
			const { delivered, gone, failed } = await sendPushBatch(
				await store.all(),
				payload,
				vapid,
			);
			await Promise.all(gone.map((endpoint) => store.delete(endpoint)));
			return json({ delivered, removed: gone.length, failed: failed.length });
		} catch (error) {
			// sendPushBatch throws only for its own inputs: VAPID config, payload size.
			return json({ error: (error as Error).message }, 400);
		}
	};

	return async (request: Request): Promise<Response> => {
		const { pathname } = new URL(request.url);
		switch (`${request.method} ${pathname}`) {
			case "GET /api/vapid-public-key":
				return json({ publicKey: vapid.publicKey });
			case "POST /api/push/subscribe":
				return saveSubscription(request);
			case "DELETE /api/push/subscribe":
				return deleteSubscription(request);
			case "POST /api/push/broadcast":
				return broadcast(request);
			default:
				return json({ error: "Not found" }, 404);
		}
	};
};
