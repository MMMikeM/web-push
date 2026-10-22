---
title: Quickstart
description: Generate VAPID keys, register a service worker, subscribe in the browser, and send from the server.
---

Four steps: generate VAPID keys once, register a service worker, subscribe in the browser, send from the server.

```bash
npm install @mmmike/web-push
```

The package is ESM-only, so a dependency tree never ends up with two copies of `WebPushError`, which would break `instanceof` checks against it. `import` works everywhere, and `require()` works on Node 22.12+ via `require(esm)`.

## 1. Generate VAPID keys

Run this once as a script and save the pair as secrets:

```ts
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
console.log({ publicKey, privateKey });
```

The public key goes to the browser; the private key never leaves your server.

## 2. Add a service worker

The browser wakes the service worker to display a push even when your page is closed:

```js
// sw.js
self.addEventListener("push", (event) => {
	const { title, body, url, tag } = event.data.json();
	event.waitUntil(
		self.registration.showNotification(title, { body, tag, data: { url } }),
	);
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	const url = event.notification.data?.url;
	if (!url) return;

	event.waitUntil(
		self.clients
			.matchAll({ type: "window", includeUncontrolled: true })
			.then((clients) => {
				const target = new URL(url, self.location.origin);
				const open =
					clients.find((client) => client.url === target.href) ??
					clients.find(
						(client) => new URL(client.url).pathname === target.pathname,
					);
				return open ? open.focus() : self.clients.openWindow(target.href);
			}),
	);
});
```

This is the receiving end of [`PushPayload`](/web-push/reference/send/#pushpayload): `title` and `body` become the notification, `tag` collapses duplicates, and `url` opens on click, focusing an already-open tab rather than opening another.

## 3. Subscribe in the browser

```ts
import { subscribe, sendSubscriptionToServer } from "@mmmike/web-push/client";

await navigator.serviceWorker.register("/sw.js");

enableButton.addEventListener("click", async () => {
	const result = await subscribe(vapidPublicKey);
	if (result.status === "subscribed") {
		await sendSubscriptionToServer(result.subscription, "/api/push/subscribe");
	}
});
```

Call `subscribe` from a click or another user gesture the first time: Safari and Firefox block a permission prompt that isn't one. Register the service worker on page load, ahead of that click, so the prompt doesn't wait on it. Once permission is granted, `subscribe` no longer prompts, so calling it on later page loads is fine.

[`subscribe`](/web-push/reference/client/#subscribe) prompts for permission if needed and resolves to one of three outcomes:

- `{ status: "subscribed", subscription, isNew }`
- `{ status: "denied" }` when the user declines the prompt
- `{ status: "unsupported" }` when the browser can't do push

Upload the subscription on every visit rather than only when `isNew` is `true`. Your endpoint has to upsert by endpoint URL anyway, and gating the upload means one failed request strands a subscription your server never hears about.

If your server needs to know who is subscribing, pass request options as the third argument:

```ts
await sendSubscriptionToServer(
	result.subscription,
	"https://api.example.com/push/subscribe",
	{
		headers: { Authorization: `Bearer ${token}` },
	},
);
```

Push needs a secure context (HTTPS or `localhost`) and a registered service worker. Without one, `subscribe` waits on `navigator.serviceWorker.ready` forever, with no error. On iOS, Safari exposes the Push API only to web apps installed to the home screen.

Encrypted-payload push works in Chrome, Edge, Firefox, Opera and Samsung Internet, and in Safari 16+ on macOS 13+ and iOS 16.4+. [`isPushSupported()`](/web-push/reference/client/#ispushsupported) is the runtime check.

## 4. Send from the server

```ts
import { sendPushNotification, WebPushError } from "@mmmike/web-push/send";

const vapid = { publicKey, privateKey, subject: "mailto:admin@example.com" };

try {
	const delivered = await sendPushNotification(
		subscription,
		{
			title: "Hello!",
			body: "You have a new message",
			url: "/messages",
			tag: "messages",
		},
		vapid,
	);
	if (!delivered) {
		// 404/410: the subscription is gone. Delete it from your store.
	}
} catch (err) {
	if (err instanceof WebPushError) {
		// The push service refused it. 429 and 5xx are worth retrying, after
		// `err.retryAfterMs` when the service sent a Retry-After header (it is
		// `null` otherwise); other statuses won't change on a retry.
	} else if (
		err instanceof TypeError ||
		(err instanceof DOMException && err.name === "TimeoutError")
	) {
		// The request never completed: DNS, TLS, a dropped connection, or no
		// answer within `timeoutMs`. Retryable.
	} else if (err instanceof DOMException && err.name === "AbortError") {
		// Your own `signal` cancelled it.
	} else {
		// Bad input: your VAPID keys, payload size or topic, or a malformed
		// subscription. Fix it or delete the subscription; a retry fails the same way.
	}
}
```

Read the VAPID keys from wherever you saved them: `env` bindings on a Worker, `process.env` on Node, `Deno.env.get` on Deno.

## Next steps

- [Build a complete app](/web-push/tutorial/) puts these four steps into one app you can run on Node or Cloudflare Workers: a notifications toggle, stored subscriptions, and a broadcast route.
- [Recipes](/web-push/guides/send-to-many/) cover single tasks: sending to many, retries, collapsing notifications, rotating keys, and authenticated uploads.
- The [API reference](/web-push/reference/) documents every export.
