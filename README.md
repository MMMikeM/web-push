# @mmmike/web-push

**The whole Web Push flow, from subscribing in the browser to sending from the server, in one zero-dependency package.**

[![npm](https://img.shields.io/npm/v/%40mmmike%2Fweb-push)](https://www.npmjs.com/package/@mmmike/web-push)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/%40mmmike%2Fweb-push)](https://bundlephobia.com/package/@mmmike/web-push)
[![CI](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml/badge.svg)](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/%40mmmike%2Fweb-push)](https://github.com/MMMikeM/web-push/blob/main/LICENSE)

Adding push notifications to a site is usually two jobs. A library handles sending, and the browser half is left to you: asking for permission, subscribing, getting the subscription to your server, and a service worker pieced together from blog posts. If you send from a Cloudflare Worker, the usual library won't build without a compatibility flag.

This package does both halves. It's built on `fetch` and the Web Crypto API instead of `node:crypto`, so the server side runs as-is on Node, Bun, Deno and Cloudflare Workers.

```bash
npm install @mmmike/web-push
```

## From zero to a notification

**1. Make a VAPID key pair, once.** The public key goes to the browser and the private key stays a server secret.

```typescript
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
```

**2. Subscribe in the browser.** Save [the quickstart's service worker](https://mmmikem.github.io/web-push/getting-started/#2-add-a-service-worker) as `/sw.js`, then:

```typescript
import { subscribe, sendSubscriptionToServer } from "@mmmike/web-push/client";

await navigator.serviceWorker.register("/sw.js");

button.addEventListener("click", async () => {
	const result = await subscribe(publicKey);
	if (result.status === "subscribed") {
		await sendSubscriptionToServer(result.subscription, "/api/push/subscribe");
	}
});
```

Safari and Firefox only show the permission prompt in response to a click, so call `subscribe` from one.

**3. Send from the server.** The payload is the `title`, `body` and `url` that service worker reads.

```typescript
import { sendPushNotification } from "@mmmike/web-push/send";

const delivered = await sendPushNotification(
	subscription,
	{ title: "New message", body: "Ada replied to your post", url: "/inbox" },
	{ publicKey, privateKey, subject: "mailto:you@example.com" },
);
// false only for 404/410, a subscription that's gone; every other failure throws
if (!delivered) await store.delete(subscription.endpoint);
```

To send one notification to a list of subscribers, see [sending to many](https://mmmikem.github.io/web-push/guides/send-to-many/).

## Specs and size

- **RFC 8291 and RFC 8292.** `aes128gcm` encryption and VAPID, pinned byte-for-byte against RFC 8291's own test vector.
- **Small.** Minified and gzipped per subpath entry, 1.2 kB for the browser client and 3.1 kB for the server. The size badge measures the whole package, ~3.9 kB.

## Coming from `web-push`?

[`web-push`](https://www.npmjs.com/package/web-push) is the established choice, and on Node it works well. Bun and Deno run it on their built-in Node compatibility. On Cloudflare Workers it fails to build without the `nodejs_compat` flag, and with the flag it ships about 51 kB gzipped of polyfills, where this package uploads about 3 kB. It also stops at the server.

[The full comparison](https://mmmikem.github.io/web-push/compare/) shows those build failures and sets this package against the edge-native alternatives too. The [migration guide](https://mmmikem.github.io/web-push/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.

## Docs

- The [quickstart](https://mmmikem.github.io/web-push/getting-started/) goes from VAPID keys to a first notification.
- [Build a complete app](https://mmmikem.github.io/web-push/tutorial/) walks through one app that runs on Node, Bun, Deno or Cloudflare Workers.
- The [recipes](https://mmmikem.github.io/web-push/guides/send-to-many/) cover sending to many, handling errors, rotating keys, extension service workers, and [securing endpoints](https://mmmikem.github.io/web-push/guides/secure-endpoints/).
- The [API reference](https://mmmikem.github.io/web-push/reference/) is generated from the JSDoc.
- For LLMs, there's [`llms.txt`](https://mmmikem.github.io/web-push/llms.txt) and a Markdown copy of every page.

## License

MIT
