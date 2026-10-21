---
title: Migrate from web-push
description: Move from the web-push package, keeping your stored subscriptions and your existing service worker.
sidebar:
  order: 9
---

Your stored subscriptions, VAPID keys, and service worker all carry over. The send call changes shape:

```diff
- import webpush from "web-push";
+ import { sendPushNotification } from "@mmmike/web-push/send";

- webpush.setVapidDetails(subject, publicKey, privateKey);
- await webpush.sendNotification(subscription, JSON.stringify({ title, body }));
+ await sendPushNotification(subscription, { title, body }, { subject, publicKey, privateKey });
```

The VAPID keys are passed on each call instead of set globally, so one process can send for several applications.

## Keep your service worker: `rawPayload`

If your service worker reads its own payload shape, such as `icon`, `badge`, or `actions`, keep sending exactly what you sent before. Wrap the string you were passing to `web-push` in [`rawPayload`](/web-push/reference/send/#rawpayload), and it's encrypted and delivered byte for byte:

```ts
import { rawPayload, sendPushNotification } from "@mmmike/web-push/send";

await sendPushNotification(
	subscription,
	rawPayload(JSON.stringify(notification)),
	vapid,
);
```

There's deliberately no bare-string form. A string passed by mistake would type-check, deliver, and only fail inside `event.data.json()` on the device; the wrapper keeps opting out of the typed payload visible where it happens.

## Three behaviours that differ

- **The default TTL is 24 hours, not four weeks.** If you relied on `web-push`'s default, pass `{ ttl: 2419200 }`.
- **A gone subscription resolves `false` instead of throwing.** A 404 or 410 means delete the subscription. Other push service errors throw a [`WebPushError`](/web-push/reference/send/#webpusherror), as `web-push` throws its own error.
- **Sending many at once has its own function.** Replace a loop over `sendNotification` with [`sendPushBatch`](/web-push/guides/send-to-many/), which bounds concurrency and sorts the results.
