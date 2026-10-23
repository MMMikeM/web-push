# @mmmike/web-push

**The whole Web Push flow, from subscribing in the browser to sending from the server, in one zero-dependency package.**

[![npm](https://img.shields.io/npm/v/%40mmmike%2Fweb-push?style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/@mmmike/web-push)
[![minzipped size](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fdeno.bundlejs.com%2F%3Fq%3D%2540mmmike%252Fweb-push&query=%24.size.compressedSize&label=minzipped%20size&style=flat&colorA=000000&colorB=000000)](https://bundlejs.com/?q=%40mmmike%2Fweb-push)
[![CI](https://img.shields.io/github/actions/workflow/status/MMMikeM/web-push/ci.yml?branch=main&label=CI&style=flat&colorA=000000)](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml)
[![delivers to Chrome and Firefox](https://img.shields.io/github/actions/workflow/status/MMMikeM/web-push/browsers.yml?branch=main&label=delivers%20to%20Chrome%20%26%20Firefox&style=flat&colorA=000000)](https://github.com/MMMikeM/web-push/actions/workflows/browsers.yml)
[![coverage](https://img.shields.io/badge/coverage-100%25-000000?style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/%40mmmike%2Fweb-push?style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/blob/main/LICENSE)

[![Node 22.12+](https://img.shields.io/badge/Node-22.12%2B-000000?logo=nodedotjs&logoColor=white&style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/conformance.yml)
[![Deno](https://img.shields.io/badge/Deno-000000?logo=deno&logoColor=white&style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/conformance.yml)
[![Bun](https://img.shields.io/badge/Bun-000000?logo=bun&logoColor=white&style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/conformance.yml)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-000000?logo=cloudflareworkers&logoColor=white&style=flat&colorA=000000&colorB=000000)](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/conformance.yml)

Adding push notifications to a site is usually two jobs. A library handles sending, and the browser half is left to you: asking for permission, replacing a subscription made with an old VAPID key, serialising the subscription for your server (`getKey()` returns `ArrayBuffer`s, which JSON can't hold), and a service worker pieced together from blog posts. The usual library is also built on Node's `crypto` and `https`, so outside Node it runs on each runtime's emulation of Node.

This package does both halves. It's built on `fetch` and the Web Crypto API, which Node, Bun, Deno and Cloudflare Workers each implement natively, so the server side runs the same on all of them with no Node emulation underneath.

To see it work first, [send yourself a notification](https://web-push.thelazyweb.dev/#try-it) from the docs site. A Cloudflare Worker encrypts and sends it with this package.

```bash
npm install @mmmike/web-push
```

## From zero to a notification

**1. Make a VAPID key pair, once.** The public key goes to the browser and the private key stays a server secret.

```typescript
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
```

**2. Subscribe in the browser.** Save [the quickstart's service worker](https://web-push.thelazyweb.dev/getting-started/#2-add-a-service-worker) as `/sw.js`, then:

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

To send one notification to a list of subscribers, `sendPushBatch` caps how many sends run at once and sorts the results into delivered, gone and failed. See [sending to many](https://web-push.thelazyweb.dev/guides/send-to-many/).

## Specs and size

- **[RFC 8291](https://www.rfc-editor.org/rfc/rfc8291) and [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292#section-3).** `aes128gcm` encryption and VAPID. There's no dependency tree to audit, the crypto is one file ([`src/encrypt.ts`](https://github.com/MMMikeM/web-push/blob/main/src/encrypt.ts)), and [a test](https://github.com/MMMikeM/web-push/blob/main/test/rfc8291-vector.test.ts) pins its output byte-for-byte to [RFC 8291's Appendix A test vector](https://www.rfc-editor.org/rfc/rfc8291#appendix-A).
- **Browsers.** Chrome, Edge, Firefox, Opera and Samsung Internet, Safari 16+ on macOS 13+, and Safari on iOS 16.4+ for web apps added to the home screen.
- **Small.** Minified and gzipped per subpath entry, 1.3 kB for the browser client and 3.6 kB for the server. The size badge measures the whole package, ~4.6 kB.

## Coming from `web-push`?

[`web-push`](https://www.npmjs.com/package/web-push) is the established choice, and on Node it works well. Elsewhere it runs on each runtime's emulation of Node, and on Deno, Supabase and Cloudflare Workers that emulation has broken it before being fixed. It also brings 16 packages: a minimal Worker that sends with it uploads about 49 kB gzipped and starts about 14 ms slower, where one using this package uploads about 4 kB. And it stops at the server.

[The full comparison](https://web-push.thelazyweb.dev/compare/) has the measurements and the bug history, and sets this package against the edge-native alternatives too. The [migration guide](https://web-push.thelazyweb.dev/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.

## Docs

- The [quickstart](https://web-push.thelazyweb.dev/getting-started/) goes from VAPID keys to a first notification.
- [Build a complete app](https://web-push.thelazyweb.dev/tutorial/) walks through one app that runs on Node, Bun, Deno or Cloudflare Workers.
- The [recipes](https://web-push.thelazyweb.dev/guides/send-to-many/) cover sending to many, handling errors, rotating keys, extension service workers, and [securing endpoints](https://web-push.thelazyweb.dev/guides/secure-endpoints/).
- The [API reference](https://web-push.thelazyweb.dev/reference/) is generated from the JSDoc.
- For LLMs, there's [`llms.txt`](https://web-push.thelazyweb.dev/llms.txt) and a Markdown copy of every page.

## License

MIT
