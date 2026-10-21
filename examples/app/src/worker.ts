import type { PushSubscriptionData } from "@mmmike/web-push";
import { createApp } from "./app.ts";
import type { SubscriptionStore } from "./store.ts";

type Env = {
	VAPID_PUBLIC_KEY: string;
	VAPID_PRIVATE_KEY: string;
	VAPID_SUBJECT: string;
	ADMIN_TOKEN: string;
	SUBSCRIPTIONS: KVNamespace;
};

const kvStore = (kv: KVNamespace): SubscriptionStore => ({
	put: (subscription) =>
		kv.put(subscription.endpoint, JSON.stringify(subscription)),
	delete: (endpoint) => kv.delete(endpoint),
	all: async () => {
		const subscriptions: PushSubscriptionData[] = [];
		let cursor: string | undefined;
		do {
			// Pages load in turn: each cursor comes from the page before.
			// oxlint-disable-next-line no-await-in-loop
			const page = await kv.list({ cursor });
			// oxlint-disable-next-line no-await-in-loop
			const values = await Promise.all(
				page.keys.map(({ name }) => kv.get<PushSubscriptionData>(name, "json")),
			);
			subscriptions.push(...values.filter((value) => value !== null));
			cursor = page.list_complete ? undefined : page.cursor;
		} while (cursor);
		return subscriptions;
	},
});

// Static files in public/ are served by Workers Static Assets before this runs,
// so only /api requests reach the app.
export default {
	fetch: (request, env) =>
		createApp({
			vapid: {
				publicKey: env.VAPID_PUBLIC_KEY,
				privateKey: env.VAPID_PRIVATE_KEY,
				subject: env.VAPID_SUBJECT,
			},
			adminToken: env.ADMIN_TOKEN,
			store: kvStore(env.SUBSCRIPTIONS),
		})(request),
} satisfies ExportedHandler<Env>;
