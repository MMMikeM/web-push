---
title: Handle push errors and retries (404, 410, 429)
description: Tell retryable failures from permanent ones, delete subscriptions that return 404 or 410, back off by Retry-After on a 429, and retry a batch's failures.
sidebar:
  label: Handle errors and retries
  order: 2
---

A send ends in one of six ways, and only some are worth retrying:

| Outcome                              | Meaning                                                                             | What to do                         |
| ------------------------------------ | ----------------------------------------------------------------------------------- | ---------------------------------- |
| Resolves `true`                      | The push service accepted the message                                               | Nothing                            |
| Resolves `false`                     | The subscription is gone (404 or 410)                                               | Delete it                          |
| Throws `WebPushError`                | The push service refused it; `statusCode` says why                                  | Depends on the status, below       |
| Throws `TypeError` or `TimeoutError` | The request never completed: network, TLS, or no answer                             | Retry                              |
| Throws `AbortError`                  | Your own `signal` cancelled it                                                      | Nothing                            |
| Throws a plain `Error`               | Bad input: your VAPID config, payload size, or `topic`, or a malformed subscription | Fix it, or delete the subscription |

## Push service statuses

[`WebPushError`](/web-push/reference/send/#webpusherror) carries the push service's `statusCode` and response `body`:

- **429** is rate limiting. Wait and retry.
- **5xx** is the push service's own fault. Retry with backoff.
- **401 or 403** usually means the VAPID keys don't match the ones the subscription was created with. See [Rotate VAPID keys](/web-push/guides/rotate-vapid-keys/).
- **400 or 413** means the request itself is wrong. A retry fails again.

When the push service sends a `Retry-After` header, `retryAfterMs` holds it as milliseconds from now. It is `null` otherwise, so fall back to your own delay.

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

[`sendPushBatch`](/web-push/reference/send/#sendpushbatch) never throws for a single subscription; its failures come back in `failed`, keyed by endpoint. Keep a map from endpoint to subscription so you can send the retryable ones again:

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

## Logging failures

A subscription endpoint is a secret: anyone holding it can push to that device. `WebPushError` truncates its endpoint and body when serialized, so a structured logger that logs the error object is safe. If you log fields by hand, prefer `statusCode` and `retryAfterMs`, and leave the endpoint out.
