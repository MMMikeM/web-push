# @mmmike/web-push

**The whole Web Push flow in one zero-dependency package that runs on every modern runtime.**

[![npm](https://img.shields.io/npm/v/%40mmmike%2Fweb-push)](https://www.npmjs.com/package/@mmmike/web-push)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/%40mmmike%2Fweb-push)](https://bundlephobia.com/package/@mmmike/web-push)
[![CI](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml/badge.svg)](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/%40mmmike%2Fweb-push)](https://github.com/MMMikeM/web-push/blob/main/LICENSE)

Sending a push notification should not require Node, a compatibility shim, or three packages that each cover a third of the flow. This is Web Push (RFC 8291) built on the Web Crypto API that every modern runtime already ships: subscribe in the browser, send from the server, the same code either side, nothing to polyfill.

- **All four pieces.** VAPID key generation, a copy-paste service worker to display the notification, the client subscribe helpers, and the server send, one at a time or fanned out to a list.
- **No Node built-ins, no polyfills.** If it has `fetch` and `crypto.subtle`, it works. No `node:crypto`, no `node:https`, no compat layer. Cloudflare Workers, Bun, Deno, Node, and the browser.
- **Ratified specs.** RFC 8291 `aes128gcm` encryption and RFC 8292 VAPID, pinned byte-for-byte against RFC 8291's Appendix A test vector.
- **Small.** Minified and gzipped per subpath entry: 0.9 kB for the browser client, 2.7 kB for the server. The badge above measures the whole package, ~3.4 kB.

## Installation

```bash
npm install @mmmike/web-push
```

**ESM-only.** `import` works everywhere, and `require()` works on Node 22.12+ via `require(esm)`. Shipping both formats would let two copies of `WebPushError` coexist in one dependency tree and silently break `instanceof` against it.

## Usage

Four steps: generate VAPID keys once, register a service worker, subscribe in the browser, send from the server.

### 1. Generate VAPID keys (once)

Run this once as a script and save the pair as secrets:

```typescript
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
console.log({ publicKey, privateKey });
```

### 2. The service worker

Push needs a service worker, because the browser wakes it to display the notification even when your page is closed. Without one registered, `subscribeToPush` waits on `navigator.serviceWorker.ready` forever.

```javascript
// sw.js
self.addEventListener("push", (event) => {
	const { title, body, url, tag } = event.data.json();
	event.waitUntil(self.registration.showNotification(title, { body, tag, data: { url } }));
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	const url = event.notification.data?.url;
	if (!url) return;

	event.waitUntil(
		self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
			const open = clients.find((client) => new URL(client.url).pathname === url);
			return open ? open.focus() : self.clients.openWindow(url);
		}),
	);
});
```

This is the receiving end of `PushPayload`: `title` and `body` become the notification, `tag` collapses duplicates, and `url` opens on click, focusing an already-open tab rather than stacking up new windows.

### 3. Client: subscribe

```typescript
import { subscribeToPush, sendSubscriptionToServer } from "@mmmike/web-push/client";

await navigator.serviceWorker.register("/sw.js");

const result = await subscribeToPush(vapidPublicKey);
if (result.status === "subscribed") {
	await sendSubscriptionToServer(result.subscription, "/api/push/subscribe");
}
```

`subscribeToPush` resolves to `{ status: "unsupported" }` when the browser can't do push, `{ status: "denied" }` when the user declines the permission prompt, and `{ status: "subscribed", subscription, isNew }` otherwise. `isNew` is `true` when this call created the subscription: a first subscribe, or a VAPID key rotation replacing the stale one.

POST the subscription on every visit rather than gating on `isNew`. Your endpoint has to upsert by endpoint URL anyway, since the browser hands back the same subscription on every call, and gating means one failed upload strands a subscription your server never hears about. Use `isNew` for what it does tell you: counting fresh subscribes and key rotations.

Requirements:

- a secure context (HTTPS or `localhost`)
- a registered service worker
- on iOS, the site installed to the home screen. Safari exposes the Push API only to installed web apps, so `isPushSupported()` reports `false` in a plain iOS Safari tab.

Encrypted-payload push works in Chrome, Edge, Firefox, Opera and Samsung Internet, and in Safari 16+ on macOS 13+ and iOS 16.4+. `isPushSupported()` is the runtime check.

Rotating VAPID keys is handled for you: when the existing subscription was created with a different key, `subscribeToPush` unsubscribes it and creates a fresh one (`isNew: true`), since the push service would reject the old one anyway. The one gap is a browser that doesn't expose which key a subscription was bound to (`subscription.options.applicationServerKey` is null): with nothing to compare against, the existing subscription is kept. If it was in fact bound to a retired key, every send to it fails with a 401/403 `WebPushError`, and nothing in that error names the rotation as the cause; if you rotate keys and then see those, this is where to look.

### 4. Server: send

```typescript
import { sendPushNotification, WebPushError } from "@mmmike/web-push/send";

// Read these from wherever you saved the vapid secrets earlier:
// `env` bindings on a Worker, `process.env` on Node, `Deno.env.get` on Deno.
const vapid = { publicKey, privateKey, subject: "mailto:admin@example.com" };

try {
	const delivered = await sendPushNotification(
		subscription, // PushSubscriptionData from the client
		{ title: "Hello!", body: "You have a new message", url: "/messages", tag: "messages" },
		vapid,
	);
	if (!delivered) {
		// 404/410: the subscription is gone. Delete it from your store.
	}
} catch (err) {
	if (err instanceof WebPushError) {
		// The push service rejected it. `err.statusCode` is its status, and
		// `err.retryAfterMs` is the Retry-After header parsed to milliseconds
		// (`err.retryAfter` keeps it verbatim). Back off, retry.
	} else if (err instanceof TypeError) {
		// `fetch` never reached the push service: DNS, TLS, timeout. Retryable.
	} else {
		// Your input: bad VAPID subject or keys, oversized payload, invalid topic.
		// Fix it, don't retry.
	}
}
```

An optional fourth argument accepts `ttl`, `vapidExpiration`, `urgency`, `topic`, a `logger`, an abort `signal`, and a per-request `timeoutMs`. The timeout defaults to 30 seconds, so a push service that accepts the connection and never responds can't hold the socket indefinitely.

> **`ttl` and `vapidExpiration` are independent settings.** `ttl` tells the push service how long to keep retrying an undelivered message, and multi-day values are normal there. `vapidExpiration` is the auth token's lifetime, which RFC 8292 caps at 24 hours. Reuse your `ttl` for it and every send past that cap comes back as a `401`.

A complete deployable Worker lives in [`examples/cloudflare-worker/`](https://github.com/MMMikeM/web-push/tree/main/examples/cloudflare-worker).

## Sending to many subscriptions

`sendPushBatch` fans one notification out through a worker pool with bounded concurrency (default 100 in flight), so ten thousand subscriptions never become ten thousand simultaneous sockets. Per-subscription failures never reject the batch; the result sorts every subscription into `delivered`, `gone`, or `failed`:

```typescript
import { sendPushBatch, WebPushError } from "@mmmike/web-push/send";

const { delivered, gone, failed } = await sendPushBatch(subscriptions, payload, vapid);
console.log(`delivered ${delivered} of ${subscriptions.length}`);

// gone: endpoints that answered 404/410. Delete them from your store.
await removeSubscriptions(gone);

// failed: every send that didn't deliver, with its error. A WebPushError
// carries statusCode and retryAfterMs, the inputs for your retry policy.
for (const { endpoint, error } of failed) {
	if (error instanceof WebPushError && error.statusCode === 429) {
		queueRetry(endpoint, error.retryAfterMs);
	}
}
```

Caller mistakes (a bad VAPID config, an oversized payload, an invalid topic) throw before anything is sent, rather than surfacing as ten thousand identical entries in `failed`. The optional fourth argument accepts everything `sendPushNotification` does, plus `concurrency`; aborting its `signal` stops the pool from starting new sends.

One efficiency comes free at this size: the VAPID JWT is signed once per push-service origin instead of once per message, since the token is scoped to the origin and valid for the whole batch. The ephemeral ECDH key pair stays fresh per message, as RFC 8291 requires.

## Migrating from `web-push`

```diff
- import webpush from "web-push";
+ import { sendPushNotification } from "@mmmike/web-push/send";

- webpush.setVapidDetails(subject, publicKey, privateKey);
- await webpush.sendNotification(subscription, JSON.stringify({ title, body }));
+ await sendPushNotification(subscription, { title, body }, { subject, publicKey, privateKey });
```

Four behavioural differences to know about:

- **TTL defaults differ.** `web-push` defaults every send to four weeks; this package defaults to 24 hours. If you relied on the long default, pass `{ ttl: 2419200 }` explicitly.
- **Gone subscriptions resolve, not throw.** HTTP 404/410 returns `false` here, meaning delete the subscription, where `web-push` rejects. Other push-service errors throw `WebPushError` in both libraries.
- **The payload is a typed object**, not a pre-stringified blob. Its shape is what your service worker reads back with `event.data.json()`.
- **That shape is fixed.** `PushPayload` is `title`, `body`, `url` and `tag`, deliberately, because the service worker above is the other end of the same contract. If you were passing `icon`, `badge`, `data` or `actions` through `web-push`, you will need to widen the type and extend that handler to match.

## API Reference

### Client (`@mmmike/web-push/client`)

| Function                                                             | Description                                                                         |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `isPushSupported()`                                                  | Check if push is supported in this browser                                          |
| `getNotificationPermission()`                                        | Get current notification permission                                                 |
| `requestNotificationPermission()`                                    | Request notification permission                                                     |
| `subscribeToPush(vapidPublicKey)`                                    | Subscribe to push, rotating a stale-key subscription; resolves to `SubscribeResult` |
| `unsubscribeFromPush()`                                              | Unsubscribe from push notifications                                                 |
| `getCurrentSubscription()`                                           | Get the existing subscription, if any                                               |
| `serializeSubscription(sub)`                                         | Convert subscription to JSON-safe format (throws if it has no `p256dh`/`auth` key)  |
| `sendSubscriptionToServer(sub, serverEndpoint)`                      | POST subscription to your server                                                    |
| `removeSubscriptionFromServer(subscriptionEndpoint, serverEndpoint)` | DELETE subscription from your server                                                |

### Server (`@mmmike/web-push/send`)

| Export                                                         | Description                                                                                           |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `sendPushNotification(subscription, payload, vapid, options?)` | Encrypt, sign, and send a push notification                                                           |
| `sendPushBatch(subscriptions, payload, vapid, options?)`       | Fan out one notification with bounded concurrency; resolves to `{ delivered, gone, failed }`          |
| `WebPushError`                                                 | Thrown on push-service errors; carries `statusCode`, `body`, `endpoint`, `retryAfter`, `retryAfterMs` |

### VAPID (`@mmmike/web-push/vapid`)

| Function                        | Description                           |
| ------------------------------- | ------------------------------------- |
| `generateVapidKeys()`           | Generate an ECDSA P-256 key pair      |
| `createVapidJwt(options)`       | Create a VAPID JWT for authentication |
| `uint8ArrayToUrlBase64(array)`  | Encode bytes to URL-safe base64       |
| `urlBase64ToUint8Array(base64)` | Decode URL-safe base64 to bytes       |

### Types

Every type ships with per-field documentation, so your editor is the reference. The names to reach for:

| Type                   | Purpose                                                                               | Exported from            |
| ---------------------- | ------------------------------------------------------------------------------------- | ------------------------ |
| `PushSubscriptionData` | A subscription in transit, endpoint plus the `p256dh`/`auth` keys                     | root, `/send`, `/client` |
| `SubscribeResult`      | Outcome of `subscribeToPush`: `subscribed` (with `isNew`), `unsupported`, or `denied` | root, `/client`          |
| `PushPayload`          | Notification contents: title, body, click URL, grouping tag                           | root, `/send`            |
| `VapidConfig`          | Your VAPID key pair and contact subject                                               | root, `/send`            |
| `SendPushOptions`      | Per-send tuning: TTL, VAPID expiry, urgency, topic, logging, cancellation             | root, `/send`            |
| `SendPushBatchOptions` | `SendPushOptions` plus the pool's `concurrency` bound                                 | root, `/send`            |
| `SendPushBatchResult`  | Outcome of `sendPushBatch`: `delivered` count, `gone` to delete, `failed` to inspect  | root, `/send`            |
| `Logger`               | Optional debug sink                                                                   | root                     |
| `VapidJwtOptions`      | Inputs to `createVapidJwt` for signing a token by hand                                | root, `/vapid`           |

## Why not `web-push`?

The popular [`web-push`](https://www.npmjs.com/package/web-push) was the right library for the world it was built in, a world where a server meant Node on an EC2 and Node's `crypto` was the only crypto there was. It is still a fine choice and will continue working well, and it carries ~5M weekly downloads and years of production maturity.

But it is built on Node built-ins, `crypto.createECDH` for the key agreement and `https.request` for delivery, with no native Web Crypto or `fetch` path. On a non-Node runtime you are running a Node compatibility layer rather than the platform, and Cloudflare Workers is the sharpest example of what that costs.

Without the compatibility layer it does not build. On a Worker with no `nodejs_compat` flag, bundling fails with 28 module-resolution errors before workerd ever starts:

```text
✘ [ERROR] Could not resolve "crypto"

    node_modules/web-push/src/encryption-helper.js:3:23:
      3 │ const crypto = require('crypto');

  The package "crypto" wasn't found on the file system but is built into node.
  - Add the "nodejs_compat" compatibility flag to your project.
```

With the flag but a compatibility date before 2024-09-23, it bundles cleanly and then fails at send time, from unenv's stubbed HTTP client:

```text
Error: [unenv] https.request is not implemented yet!
    at Object.fn [as request] (.../index.js:67:27)
    at WebPushLib.sendNotification (.../index.js:9347:14)
```

With `nodejs_compat` and a current compatibility date, `web-push` does run on Workers ([issue #718, "Cloudflare Worker support?"](https://github.com/web-push-libs/web-push/issues/718), filed in 2022 and still open, tracks the history). That is Cloudflare's compatibility layer doing the work rather than `web-push` supporting the platform, and it is not free:

- You carry the `nodejs_compat` flag and a compatibility date of 2024-09-23 or later.
- The polyfilled `node:https` and `node:crypto` stack ships in your bundle, against a Worker's size budget: measured on the same wrangler scaffold, `web-push` uploads 49.97 KiB gzipped where this package uploads about 3 KiB gzipped. It also brings 5 direct dependencies pulling in 16 packages.
- Your crypto path runs through a shim rather than the platform's own Web Crypto.
- It is Cloudflare's fix specifically. Every other non-Node runtime needs its own Node-compatibility story, and `web-push` has no native path on any of them.

There is also the client half. Every library in this space, `web-push` included, hands you a README snippet and has you call `pushManager.subscribe()` yourself. The call itself is five lines. The fiddly parts around it are the permission flow that starts from `"default"`, the base64url encoding of the application server key, and the serialisation your server actually stores, since `getKey()` returns an `ArrayBuffer` rather than anything you can put in JSON. This package ships that half too, tested.

### Comparison

Competitor figures below are as of 1.0.1's release, August 2026.

|                                     | `web-push`                                                                     | `@pushforge/builder` | `@block65/webcrypto-web-push` | **`@mmmike/web-push`**           |
| ----------------------------------- | ------------------------------------------------------------------------------ | -------------------- | ----------------------------- | -------------------------------- |
| Runs on Workers / Deno / Bun / Edge | via Node compat ([#718](https://github.com/web-push-libs/web-push/issues/718)) | ✓                    | ✓                             | ✓ natively                       |
| Runs on Node.js                     | ✓                                                                              | ✓                    | ✓                             | ✓                                |
| Client subscribe helpers            | ✗                                                                              | ✗                    | ✗                             | ✓                                |
| Sends the request                   | ✓                                                                              | ✗ builds only        | ✗ builds only                 | ✓                                |
| VAPID key generation                | ✓                                                                              | CLI only             | ✗                             | ✓                                |
| RFC 8291 payload (`aes128gcm`)      | ✓                                                                              | ✗ draft-04 `aesgcm`  | ✗ draft-04 `aesgcm`           | ✓                                |
| RFC 8292 VAPID (`vapid t=…, k=…`)   | ✓                                                                              | ✓                    | ✗ draft `WebPush <jwt>`       | ✓                                |
| Dependencies                        | 5 direct, 16 transitive                                                        | zero                 | 3 direct                      | **zero**                         |
| Maturity / ecosystem                | **high** (3.5k★, ~5M/wk)                                                       | 39k/wk               | 30k/wk, last release 2024-12  | new: 1.0.1, RFC 8291 test vector |

Neither edge-native alternative is on the ratified specs: both encrypt with the draft-04 `aesgcm` scheme, putting the salt and DH key in `Encryption`/`Crypto-Key` headers instead of RFC 8291's binary header block, and one still authenticates with the pre-standard `Authorization: WebPush <jwt>`.

What this package asks you to trust is deliberately small: no dependency tree, one auditable crypto file ([`src/encrypt.ts`](https://github.com/MMMikeM/web-push/blob/main/src/encrypt.ts)), and its output pinned byte-for-byte against the test vector published in RFC 8291 itself.

## License

MIT
