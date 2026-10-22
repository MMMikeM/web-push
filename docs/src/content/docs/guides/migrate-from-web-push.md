---
title: Migrate from web-push
description: Move from the web-push package to @mmmike/web-push, keeping your stored subscriptions, VAPID keys and existing service worker, with a mapping of every sendNotification option.
sidebar:
  order: 9
---

Your stored subscriptions, VAPID keys, and service worker all carry over. Only the send call changes:

```diff lang="ts"
- import webpush from "web-push";
+ import { sendPushNotification } from "@mmmike/web-push/send";

- webpush.setVapidDetails(subject, publicKey, privateKey);
- await webpush.sendNotification(subscription, JSON.stringify({ title, body }));
+ await sendPushNotification(subscription, { title, body }, { subject, publicKey, privateKey });
```

The VAPID keys are passed on each call instead of set globally, so one process can send for several applications.

## Before you switch

- **Node 22.12 or later.** `web-push` supports Node 16 and up; this package's `engines` field asks for 22.12.
- **ESM only.** There is no CommonJS build. Node 22.12 and later can still load it from CommonJS with `require("@mmmike/web-push/send")`, because `require(esm)` is on by default from that version.
- **Your VAPID keys work as they are.** `web-push`'s `generateVAPIDKeys` returns a base64url 65-byte uncompressed public key and a base64url 32-byte private key, which is the format this package reads and writes. Keep the same pair and existing subscriptions stay valid.
- **Key generation is async.** `generateVAPIDKeys()` returns the keys directly; [`generateVapidKeys()`](/web-push/reference/vapid/#generatevapidkeys) returns a promise, because Web Crypto's key generation is async. Add an `await`.

## Keeping your service worker with `rawPayload`

If your service worker reads its own payload format, such as `icon`, `badge`, or `actions`, keep sending exactly what you sent before. Wrap the string you were passing to `web-push` in [`rawPayload`](/web-push/reference/send/#rawpayload), and it's encrypted and delivered byte for byte:

```ts
import { rawPayload, sendPushNotification } from "@mmmike/web-push/send";

await sendPushNotification(
	subscription,
	rawPayload(JSON.stringify(notification)),
	vapid,
);
```

There's deliberately no bare-string form. A string passed by mistake would type-check, deliver, and only fail inside `event.data.json()` on the device; the wrapper keeps opting out of the typed payload visible where it happens.

## Options

`web-push`'s `sendNotification` takes its options as the third argument. Here the VAPID keys are the third argument and the options, [`SendPushOptions`](/web-push/reference/send/#sendpushoptions), are the fourth.

| `web-push` option | `@mmmike/web-push`                                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `vapidDetails`    | The third argument, `{ subject, publicKey, privateKey }`                                                                             |
| `TTL`             | `ttl`, in seconds. The default is 24 hours where `web-push`'s is four weeks.                                                         |
| `urgency`         | `urgency`, the same four values. `web-push` sends `normal` when unset; this package leaves the header out.                           |
| `topic`           | `topic`, the same 32-character limit. [`topicFromString`](/web-push/reference/send/#topicfromstring) derives one from any string.    |
| `timeout`         | `timeoutMs`. `web-push`'s is a socket idle timeout with no default; `timeoutMs` bounds the whole request and defaults to 30 seconds. |
| `contentEncoding` | No equivalent. Every send uses `aes128gcm`; the draft `aesgcm` encoding isn't supported.                                             |
| `headers`         | No equivalent.                                                                                                                       |
| `proxy`, `agent`  | No equivalent. Requests go through the runtime's `fetch`.                                                                            |
| `gcmAPIKey`       | No equivalent. It authenticates to the legacy GCM service, which this package doesn't support.                                       |
| No equivalent     | `signal`, an `AbortSignal` that cancels the send                                                                                     |
| No equivalent     | `vapidExpiration`, the VAPID token's lifetime in seconds (default 12 hours, at most 24)                                              |
| No equivalent     | `logger`, which receives each push service response                                                                                  |

## Behaviours that differ

- **The default TTL is 24 hours, where `web-push`'s is four weeks.** If you relied on `web-push`'s default, pass `{ ttl: 2419200 }`.
- **A gone subscription resolves `false` instead of throwing.** A 404 or 410 means delete the subscription. Other push service errors throw a [`WebPushError`](/web-push/reference/send/#webpusherror), as `web-push` throws its own error.
- **Sending many at once has its own function.** Replace a loop over `sendNotification` with [`sendPushBatch`](/web-push/guides/send-to-many/), which bounds concurrency and sorts the results.
