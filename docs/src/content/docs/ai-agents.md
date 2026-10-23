---
title: Rules for AI coding agents
description: What a coding agent needs to know to write correct code with @mmmike/web-push, shipped in every release as dist/AGENTS.md for your own AGENTS.md.
sidebar:
  label: For AI coding agents
---

Every release ships the rules below inside the package, at `node_modules/@mmmike/web-push/dist/AGENTS.md`, after a list of the entry points and what each one exports. The file wraps them in start and end markers, so you can paste it into your project's own `AGENTS.md` and replace it when you upgrade.

## Rules

- **It isn't the `web-push` package.** There's no `setVapidDetails`, `sendNotification` or `generateVAPIDKeys`. Each send takes the VAPID config, `{ publicKey, privateKey, subject }`, as an argument. Keys and stored subscriptions from `web-push` work unchanged, see [Migrate from web-push](/guides/migrate-from-web-push/).
- **Server, browser and keys import from separate entry points.** `@mmmike/web-push/send` on the server, `@mmmike/web-push/client` in the page, `@mmmike/web-push/vapid` for keys and base64url. The root export re-exports all three.
- **`false` means the subscription is gone.** `sendPushNotification` resolves `true` when the push service accepts the message and `false` on a 404 or 410, so delete that subscription. The exception is a subscription the browser made seconds ago. Google's push service can answer 410 until it has registered it, so after a fresh upload, retry with growing gaps for up to a minute before deleting. Other refusals throw `WebPushError`, and only a 429 or a 5xx is worth retrying, after `retryAfterMs` when it isn't `null`. A `TypeError` or `TimeoutError` is the network and worth retrying. An `InvalidSubscriptionError` is a malformed subscription to delete, and a plain `Error` is your own bad input, which a retry won't fix. See [Handle errors and retries](/guides/handle-errors/).
- **Use `sendPushBatch` for a list of subscribers.** It signs one VAPID token per push service, runs at most 100 sends at once by default, and returns `{ delivered, gone, failed }` instead of throwing. Delete `gone` and retry from `failed`. See [Send to many](/guides/send-to-many/).
- **An object payload is sent as JSON.** Wrap a string or bytes in `rawPayload()` to send them as they are. Anything over 3993 bytes once encoded throws before a request is made.
- **`generateVapidKeys()` returns a promise.** Generate one pair per app, once, and keep the private key secret. A subscription only works with the public key it was made with, so replacing the pair means [rotating it](/guides/rotate-vapid-keys/). `subject` is a `mailto:` or `https:` URL.
- **Check each uploaded subscription with `isPushServiceEndpoint()`.** The send functions post to whatever endpoint a subscription names, so a server that takes subscriptions from browsers should refuse any endpoint that isn't on a browser's push service. See [Secure your endpoints](/guides/secure-endpoints/).
- **Register the service worker before calling `subscribe(vapidPublicKey)`.** Check the result's `status`, which can be `"unsupported"` or `"denied"` as well as `"subscribed"`. Send the subscription to your server on every load, whether or not `isNew` is true. `subscribeToPush` and `unsubscribeFromPush` are deprecated names; use `subscribe`, and `unsubscribe`, which resolves to the endpoint your server should delete.
- **Every push shows a notification.** The service worker's `push` handler has to call `showNotification`. If it shows nothing, Chrome shows a generic notification in its place, and Safari removes the subscription after three such pushes. Silent pushes need an extension's service worker, see [Extension service workers](/guides/extension-service-workers/).
- **No Node compatibility layer is needed.** It uses only `fetch` and Web Crypto, so a Cloudflare Worker needs no `nodejs_compat`, and Deno, Bun and Node 22.12+ need no polyfills.

## The rest of the docs

Every page is also Markdown. [llms.txt](https://web-push.thelazyweb.dev/llms.txt) lists them, and a page's URL with `.md` in place of its trailing slash is its Markdown copy, such as [the Quickstart](/getting-started/) or the [API reference](/reference/).
