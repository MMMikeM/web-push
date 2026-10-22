---
title: Send to many
description: Fan one notification out to every subscriber with bounded concurrency, and sort the results into delivered, gone, and failed.
sidebar:
  order: 1
---

[`sendPushBatch`](/web-push/reference/send/#sendpushbatch) sends one notification to a list of subscriptions through a pool of workers, so ten thousand subscribers never become ten thousand open sockets:

```ts
import { sendPushBatch } from "@mmmike/web-push/send";

const { delivered, gone, failed } = await sendPushBatch(
	subscriptions,
	payload,
	vapid,
);

await deleteSubscriptions(gone);
console.log(
	`${delivered} delivered, ${gone.length} gone, ${failed.length} failed`,
);
```

## What comes back

A failed send never rejects the batch. Every subscription lands in one of three places:

- **`delivered`** counts the sends the push service accepted.
- **`gone`** lists the endpoints that answered 404 or 410: the browser unsubscribed, or the subscription expired. Delete them; they will never work again.
- **`failed`** holds every other send, each with its `endpoint` and `error`. Most are worth retrying; [Handle errors and retries](/web-push/guides/handle-errors/) sorts them.

## What throws instead

Mistakes in your own input throw before anything is sent, rather than appearing ten thousand times in `failed`: a bad VAPID config, a payload over the 3,993-byte limit, an invalid `topic`, or an invalid `ttl`, `concurrency` or `timeoutMs`.

## Concurrency and other batch options

The optional fourth argument takes everything [`sendPushNotification`](/web-push/reference/send/#sendpushnotification) does, plus `concurrency`:

```ts
await sendPushBatch(subscriptions, payload, vapid, {
	concurrency: 50, // sends in flight at once; default 100
	ttl: 3600,
	signal: AbortSignal.timeout(60_000),
});
```

- **`concurrency`** bounds the sends in flight. Lower it on platforms that cap outbound connections.
- **`signal`** stops the pool from starting new sends when it aborts. Subscriptions it never reached appear in none of the three results, so compare `delivered + gone.length + failed.length` with the number you passed in.
- **`ttl`** and **`topic`** apply to every message in the batch. [Collapse and expire notifications](/web-push/guides/collapse-notifications/) explains both.

The VAPID token is signed once per push service rather than once per message, since it's scoped to the push service's origin. It's signed again at half its lifetime, so a batch that runs longer than `vapidExpiration` never sends an expired token. Each message still gets its own encryption keys, as [RFC 8291 §3.1](https://www.rfc-editor.org/rfc/rfc8291#section-3.1) requires.

## Sending to large subscriber lists

`sendPushBatch` takes an array, so it holds every subscription in memory at once. For a large list, read it from your database a page at a time and send each page as its own batch:

```ts
for await (const page of subscriptionPages(1000)) {
	const { gone, failed } = await sendPushBatch(page, payload, vapid);
	await deleteSubscriptions(gone);
	await queueRetries(failed);
}
```
