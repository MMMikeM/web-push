import type { PushSubscriptionData } from "@mmmike/web-push";

/**
 * Where subscriptions live between requests. Keyed by endpoint: the browser
 * hands back the same subscription on every visit, so `put` is an upsert.
 */
export type SubscriptionStore = {
	put(subscription: PushSubscriptionData): Promise<void>;
	delete(endpoint: string): Promise<void>;
	all(): Promise<PushSubscriptionData[]>;
};
