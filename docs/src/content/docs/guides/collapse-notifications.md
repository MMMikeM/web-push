---
title: Collapse and expire notifications
description: Replace stale notifications with tag and topic, and let undelivered ones expire with ttl.
sidebar:
  order: 3
---

Three settings decide what a user sees when you push about the same thing more than once, or while their device is offline. They work in different places:

| Setting | Read by          | Effect                                                                                |
| ------- | ---------------- | ------------------------------------------------------------------------------------- |
| `tag`   | The device       | A new notification with the same tag replaces the one already showing                 |
| `topic` | The push service | While the device is offline, a newer push with the same topic replaces the queued one |
| `ttl`   | The push service | How long an undelivered push is kept before it's dropped                              |

## Replace what's on screen: `tag`

`tag` travels inside the payload, and the service worker passes it to `showNotification`. The [example service worker](/web-push/getting-started/#2-add-a-service-worker) already does:

```ts
await sendPushNotification(
	subscription,
	{ title: "3 new messages", url: "/inbox", tag: "inbox" },
	vapid,
);
```

Send another push with `tag: "inbox"` and it replaces this notification rather than stacking a second one.

## Replace what's queued: `topic`

`topic` is an option, read by the push service before the device ever sees the push. If the device is offline, only the newest push per topic is waiting when it reconnects:

```ts
await sendPushNotification(subscription, payload, vapid, { topic: "inbox" });
```

A topic is at most 32 URL-safe base64 characters (RFC 8030 §5.4). To derive one from any string, such as a thread id or a URL, use [`topicFromString`](/web-push/reference/send/#topicfromstring). The same input always gives the same topic, so collapsing still works, and the raw value stays out of the request header:

```ts
const topic = await topicFromString(`thread:${threadId}`);
```

Use both together when you want one notification per thread, both on screen and in the queue.

## Expire what's stale: `ttl`

`ttl` is how many seconds the push service keeps trying to deliver to an offline device. The default is 24 hours. Shorten it for anything that stops mattering, such as a "your driver is outside" alert:

```ts
await sendPushNotification(subscription, payload, vapid, { ttl: 300 });
```

Don't confuse it with `vapidExpiration`, the lifetime of the VAPID token, which RFC 8292 caps at 24 hours. Setting that to a multi-day `ttl` value makes every send fail with a 401.
