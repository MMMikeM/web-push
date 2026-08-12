# @mmmike/web-push

**Subscribe, send, VAPID. One package, runs everywhere, zero dependencies.**

Web Push (RFC 8291) built entirely on the Web Crypto API: the browser-side subscription flow, the server-side send, and VAPID key generation. One install that behaves identically on Cloudflare Workers, Deno, Bun, Vercel Edge, Node.js, and in the browser.

## Features

- **The whole flow.** Client subscribe helpers, server send, and VAPID key generation.
- **Runs everywhere.** Cloudflare Workers, Deno, Bun, Vercel Edge, Node.js 22.12+, and browsers, the same code, no adapters.
- **Zero dependencies.** Only the standard Web Crypto API. No Node built-ins, and no dependency tree to audit.
- **RFC 8291 compliant.** `aes128gcm` content encoding (RFC 8188), VAPID (RFC 8292) auth, pinned byte-for-byte against RFC 8291's Appendix A test vector.
- **Small.** The whole runtime is 7.7 kB minified: the browser half is about 1.6 kB gzipped, the server half about 2.7 kB.
- **ESM-only.** No CJS interop shims in a Vite build, and the `/client` and `/send` entries split cleanly across a full-stack framework's server/client boundary (React Router, SvelteKit, Nuxt and friends).
- **TypeScript.** Full type definitions, four subpath entry points so you import only what you use.

## Why not `web-push`?

The popular [`web-push`](https://www.npmjs.com/package/web-push) was the right library for the world it was built in: a server meant Node on an EC2, and Node's `crypto` was the only crypto there was. It is still a fine choice and will continue working well, and it carries ~5M weekly downloads and years of production maturity.

Web Crypto and `fetch` are now standard on every runtime that matters, from Workers to Bun to the browser itself, and a Web Push implementation no longer needs Node to exist. This package is what web-push looks like when it is built for the platform we have now.

`web-push` itself is built on Node built-ins, `crypto.createECDH` for the key agreement and `https.request` for delivery. There is no native Web Crypto or `fetch` path in it, so on a non-Node runtime you are relying on a Node compatibility layer rather than the platform. Cloudflare Workers is the sharpest example of what carrying that costs.

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

With `nodejs_compat` and a current compatibility date, `web-push` does run on Workers ([issue #718, "Cloudflare Worker support?"](https://github.com/web-push-libs/web-push/issues/718), filed in 2022 and still open, tracks the history). That is a shim, not support, and it is not free:

- You carry the `nodejs_compat` flag and a compatibility date of 2024-09-23 or later.
- The polyfilled `node:https` and `node:crypto` stack ships in your bundle, against a Worker's size budget: measured on the same wrangler scaffold, `web-push` uploads 262.53 KiB (49.97 KiB gzipped) where this package uploads under 12 KiB (~3 KiB gzipped). It also brings 5 direct dependencies pulling in 16 packages.
- Your crypto path runs through a shim rather than the platform's own Web Crypto.
- It is Cloudflare's fix specifically. Every other non-Node runtime needs its own Node-compatibility story, and web-push has no native path on any of them.

It also only sends. There are no client-side subscription helpers; its README shows you calling `pushManager.subscribe()` yourself.

This library uses only the Web Crypto API (`crypto.subtle`) and `fetch`, both standard in every modern runtime, so the same code runs on the edge, on Node, and in the browser with zero dependencies and no compatibility flags.

### Comparison

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
| Maturity / ecosystem                | **high** (3.5k★, ~5M/wk)                                                       | 39k/wk               | 30k/wk, last release 2024-12  | new: 1.0.0, RFC 8291 test vector |

No other library ships client-side subscription helpers; all three hand you a README snippet and let you write `pushManager.subscribe()` yourself. And neither edge-native alternative is on the ratified specs: both encrypt with the draft-04 `aesgcm` scheme, putting the salt and DH key in `Encryption`/`Crypto-Key` headers instead of RFC 8291's binary header block, and one still authenticates with the pre-standard `Authorization: WebPush <jwt>`.

The whole flow, end to end, on the ratified spec, 7.7 kB, zero dependencies for your security team to audit, no compatibility flags that you might miss.

The saving is not edge-specific either; on a Lambda or any serverless Node, one package instead of seventeen is less to parse at cold start, less to audit, and less to update.
This is the new default answer, for any project, on any runtime.

## Installation

```bash
npm install @mmmike/web-push
```

**ESM-only.** The package ships a single ES module build, no CommonJS. `import` works everywhere; `require()` works on Node 22.12+, which added `require(esm)`. Shipping both formats would let two copies of `WebPushError` coexist in one dependency tree and silently break `instanceof` against it.

## Usage

### Generate VAPID Keys

```typescript
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
// Store these securely - publicKey goes to client, privateKey stays on server
```

### Client-Side: Subscribe to Push

```typescript
import { subscribeToPush, sendSubscriptionToServer } from "@mmmike/web-push/client";

// Subscribe user to push notifications
const subscription = await subscribeToPush(vapidPublicKey);

if (subscription) {
  // Send subscription to your server
  await sendSubscriptionToServer(subscription, "/api/push/subscribe");
}
```

### Server-Side: Send Notifications

Runs unchanged on a Cloudflare Worker, Deno, Bun, Vercel Edge, or Node.js. See [`examples/cloudflare-worker/`](examples/cloudflare-worker/) for a deployable Worker.

```typescript
import { sendPushNotification } from "@mmmike/web-push/send";

const success = await sendPushNotification(
  subscription, // PushSubscriptionData from client
  {
    title: "Hello!",
    body: "You have a new message",
    url: "/messages", // opened when the notification is clicked
    tag: "messages", // optional grouping/replacement key
  },
  {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
    subject: "mailto:admin@example.com",
  },
);
```

`sendPushNotification` returns `true` on success, `false` when the subscription is gone (HTTP 404/410, delete it), and throws a `WebPushError` (with `statusCode`, `body`, `endpoint`, `retryAfter`) on rate limits and other push-service errors. An optional fourth `options` argument accepts `ttl`, `vapidExpiration`, `urgency`, `topic`, and a `logger`.

Handling all three outcomes:

```typescript
import { sendPushNotification, WebPushError } from "@mmmike/web-push/send";

try {
  const delivered = await sendPushNotification(subscription, payload, vapid);
  if (!delivered) {
    // 404/410, the subscription is gone. Delete it from your store.
  }
} catch (err) {
  if (err instanceof WebPushError) {
    // The push service rejected it. `err.statusCode` is its status;
    // `err.retryAfter` carries the Retry-After header on a 429.
  }
  // Anything else is malformed input, bad VAPID subject or keys,
  // oversized payload, invalid topic.
}
```

## API Reference

### Client-Side (`@mmmike/web-push/client`)

| Function                                                 | Description                                                                        |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `isPushSupported()`                                      | Check if push is supported in browser                                              |
| `getNotificationPermission()`                            | Get current notification permission                                                |
| `requestNotificationPermission()`                        | Request notification permission                                                    |
| `subscribeToPush(vapidPublicKey)`                        | Subscribe to push notifications                                                    |
| `unsubscribeFromPush()`                                  | Unsubscribe from push notifications                                                |
| `getCurrentSubscription()`                               | Get existing subscription if any                                                   |
| `serializeSubscription(sub)`                             | Convert subscription to JSON-safe format (throws if it has no `p256dh`/`auth` key) |
| `sendSubscriptionToServer(sub, endpoint)`                | POST subscription to your server                                                   |
| `removeSubscriptionFromServer(endpoint, serverEndpoint)` | DELETE subscription from server                                                    |

### Server-Side (`@mmmike/web-push/send`)

| Export                                                         | Description                                                                           |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `sendPushNotification(subscription, payload, vapid, options?)` | Send a push notification                                                              |
| `WebPushError`                                                 | Thrown on push-service errors; carries `statusCode`, `body`, `endpoint`, `retryAfter` |

### VAPID Utilities (`@mmmike/web-push/vapid`)

| Function                        | Description                         |
| ------------------------------- | ----------------------------------- |
| `generateVapidKeys()`           | Generate ECDSA P-256 key pair       |
| `createVapidJwt(options)`       | Create VAPID JWT for authentication |
| `uint8ArrayToUrlBase64(array)`  | Encode bytes to URL-safe base64     |
| `urlBase64ToUint8Array(base64)` | Decode URL-safe base64 to bytes     |

## Types

Every type ships with the package and carries per-field documentation, so your editor is the reference. These are the names to reach for:

| Type                   | Purpose                                                                 | Exported from            |
| ---------------------- | ----------------------------------------------------------------------- | ------------------------ |
| `PushSubscriptionData` | A subscription in transit, endpoint plus the `p256dh`/`auth` keys       | root, `/send`, `/client` |
| `PushPayload`          | Notification contents: title, body, click URL, grouping tag             | root, `/send`            |
| `VapidConfig`          | Your VAPID key pair and contact subject                                 | root, `/send`            |
| `SendPushOptions`      | Per-send tuning: `ttl`, `vapidExpiration`, `urgency`, `topic`, `logger` | root, `/send`            |
| `Logger`               | Optional debug sink                                                     | root                     |
| `VapidJwtOptions`      | Inputs to `createVapidJwt` for signing a token by hand                  | root, `/vapid`           |

`ttl` and `vapidExpiration` are independent settings. `ttl` tells the push service how long to keep retrying an undelivered message, and multi-day values are normal there. `vapidExpiration` is the auth token's lifetime, which RFC 8292 caps at 24 hours. Reuse your `ttl` for it and every send past that cap comes back as a `401`.

## License

MIT
