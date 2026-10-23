---
title: Handle push errors and retries (404, 410, 429)
description: Tell retryable failures from permanent ones, delete subscriptions that return 404 or 410, back off by Retry-After on a 429, and retry a batch's failures.
sidebar:
  label: Handle errors and retries
  order: 2
---

A send ends in one of seven ways, and only some are worth retrying:

| Outcome                              | Meaning                                                                                   | What to do                   |
| ------------------------------------ | ----------------------------------------------------------------------------------------- | ---------------------------- |
| Resolves `true`                      | The push service accepted the message                                                     | Nothing                      |
| Resolves `false`                     | The subscription is gone (404 or 410)                                                     | Delete it                    |
| Throws `WebPushError`                | The push service refused it; `statusCode` says why                                        | Depends on the status, below |
| Throws `TypeError` or `TimeoutError` | The request never completed: network, TLS, or no answer                                   | Retry                        |
| Throws `AbortError`                  | Your own `signal` cancelled it                                                            | Nothing                      |
| Throws `InvalidSubscriptionError`    | The subscription is malformed: its endpoint isn't `https:`, or a key is missing or broken | Delete it                    |
| Throws a plain `Error`               | Your own input is wrong: the VAPID config, payload size, `topic`, `ttl` or `timeoutMs`    | Fix it                       |

## Push service statuses

[`WebPushError`](/reference/send/#webpusherror) carries the push service's `statusCode` and response `body`:

- **429** is rate limiting. Wait and retry.
- **5xx** is the push service's own fault. Retry with backoff.
- **401 or 403** usually means the VAPID keys don't match the ones the subscription was created with. See [Rotate VAPID keys](/guides/rotate-vapid-keys/).
- **400 or 413** means the request itself is wrong. A retry fails again.

When the push service sends a `Retry-After` header, `retryAfterMs` holds it as milliseconds from now. It is `null` otherwise, so fall back to your own delay.

## Right after subscribing

Google's push service can answer 410 for a subscription made moments earlier, before it has finished registering it. In our tests with new Chrome profiles it did so for 8 of 42 fresh subscriptions. Six were accepted 2 to 6 seconds later, and two were still refused after 6.

A subscription can't really be gone seconds after a browser made it, so a send that closely follows the upload, such as a welcome notification, should read `false` as "not yet". Retry with growing gaps for up to a minute before deleting it:

```ts
import { sendPushNotification } from "@mmmike/web-push/send";

const sendToNewSubscription = async (subscription, payload, vapid) => {
	for (const waitMs of [0, 2_000, 4_000, 8_000, 16_000, 32_000]) {
		await new Promise((resolve) => setTimeout(resolve, waitMs));
		if (await sendPushNotification(subscription, payload, vapid)) {
			return true;
		}
	}
	return false;
};
```

Subscriptions your server has held for longer don't need this; for them, `false` means gone.

## A retry decision

```ts
import { WebPushError } from "@mmmike/web-push/send";

const isRetryable = (error: unknown): boolean => {
	if (error instanceof WebPushError) {
		return error.statusCode === 429 || error.statusCode >= 500;
	}
	return (
		error instanceof TypeError ||
		(error instanceof DOMException && error.name === "TimeoutError")
	);
};

const retryDelayMs = (error: unknown, attempt: number): number =>
	(error instanceof WebPushError ? error.retryAfterMs : null) ??
	1000 * 2 ** attempt;
```

An `AbortError` only happens when your own `signal` aborts, so it isn't retried here.

Before 1.4.0, a malformed subscription could also throw a `TypeError`, and this check would retry it forever. Upgrade before relying on it.

## Retrying a batch

[`sendPushBatch`](/reference/send/#sendpushbatch) never throws for a single subscription; its failures come back in `failed`, keyed by endpoint. Keep a map from endpoint to subscription so you can send the retryable ones again:

```ts
const byEndpoint = new Map(
	subscriptions.map((subscription) => [subscription.endpoint, subscription]),
);
const { failed } = await sendPushBatch(subscriptions, payload, vapid);

const retry = failed
	.filter(({ error }) => isRetryable(error))
	.flatMap(({ endpoint }) => byEndpoint.get(endpoint) ?? []);
```

Schedule `retry` for later through a queue rather than in a loop, so one slow push service can't hold up the rest.

## In the browser

Deleting a gone subscription on your server doesn't reach the browser, which can go on holding it, and [`subscribe`](/reference/client/#subscribe) hands back the subscription a browser already holds for the same key. If your server remembers the endpoints it deleted as gone and refuses them when a page uploads one, the page can swap it for a fresh subscription:

```ts
import {
	sendSubscriptionToServer,
	subscribe,
	unsubscribe,
} from "@mmmike/web-push/client";

const result = await subscribe(vapidPublicKey);
if (
	result.status === "subscribed" &&
	!(await sendSubscriptionToServer(result.subscription))
) {
	// Refused: replace it once, rather than retrying in a loop.
	await unsubscribe();
	const fresh = await subscribe(vapidPublicKey);
	if (fresh.status === "subscribed") {
		await sendSubscriptionToServer(fresh.subscription);
	}
}
```

## Logging failures

A subscription endpoint is a secret: anyone holding it can push to that device. `WebPushError` truncates its endpoint and body when serialized, so a structured logger that logs the error object is safe. If you log fields by hand, prefer `statusCode` and `retryAfterMs`, and leave the endpoint out.
