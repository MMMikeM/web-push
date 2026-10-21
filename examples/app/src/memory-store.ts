import type { PushSubscriptionData } from "@mmmike/web-push";
import type { SubscriptionStore } from "./store.ts";

/**
 * Lost on restart. Swap in a database; anything that can upsert by endpoint
 * will do.
 */
export const memoryStore = (): SubscriptionStore => {
	const subscriptions = new Map<string, PushSubscriptionData>();
	return {
		put: async (subscription) => {
			subscriptions.set(subscription.endpoint, subscription);
		},
		delete: async (endpoint) => {
			subscriptions.delete(endpoint);
		},
		all: async () => [...subscriptions.values()],
	};
};
