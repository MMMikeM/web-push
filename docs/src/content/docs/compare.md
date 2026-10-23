---
title: "@mmmike/web-push vs alternatives"
description: How @mmmike/web-push compares to web-push, PushForge, block65, web-push-neo and @negrel/webpush on size, sending, spec tests and CI coverage.
sidebar:
  label: How it compares
tableOfContents:
  maxHeadingLevel: 2
head:
  - tag: title
    content: "@mmmike/web-push vs alternatives"
---

`@mmmike/web-push` and [`web-push`](https://www.npmjs.com/package/web-push) are separate packages by different authors. `web-push` is the [web-push-libs](https://github.com/web-push-libs/web-push) Node library, on npm since 2015 and the one most Web Push tutorials use. `@mmmike/web-push` is a newer package that shares no code with it.

Both send the same standard notifications. `web-push` is built on Node's `crypto` and `https` modules, and `@mmmike/web-push` on `fetch` and Web Crypto, which Cloudflare Workers, Deno, Bun, Node and browsers each implement natively. Subscriptions and VAPID keys work with either, so switching keeps the ones you've stored.

## Candidates

<details>
<summary>About each candidate</summary>

### @mmmike/web-push

[npm](https://www.npmjs.com/package/@mmmike/web-push) · [GitHub](https://github.com/MMMikeM/web-push)

Subscribes in the browser and sends from the server, one notification or a whole list, with no dependencies. Gone subscriptions resolve `false`, `Retry-After` arrives parsed, and every request has a timeout. It's [tested against RFC 8291's example](https://github.com/MMMikeM/web-push/blob/main/test/rfc8291-vector.test.ts), [in CI on Node, Deno, Bun and Workers](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/conformance.yml), and [by real delivery to Chrome and Firefox](https://github.com/MMMikeM/web-push/blob/main/.github/workflows/browsers.yml).

### web-push

[npm](https://www.npmjs.com/package/web-push) · [GitHub](https://github.com/web-push-libs/web-push)

The established Node library, at about 6.6M downloads a week, built on Node's `crypto` and `https` with 16 packages. Outside Node it relies on the runtime's emulation of those modules. A minimal Cloudflare Worker that sends one notification uploads 51 kB gzipped with it and takes longer to start. With `@mmmike/web-push` it uploads 5.1 kB and starts as fast as an empty Worker. [CI measures both](https://github.com/MMMikeM/web-push/actions/workflows/ci.yml) on every push. It throws on every response outside 2xx, so telling a gone subscription from a failure is up to you. See [Migrate from web-push](/guides/migrate-from-web-push/).

Each of these broke `web-push` until the runtime fixed it:

| Runtime            | What broke                                                                                                                             | Until        |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| Deno               | [Chrome couldn't decrypt the payloads](https://github.com/denoland/deno/issues/23693), so notifications never arrived                  | August 2024  |
| Supabase           | [Signing with an EC private key](https://github.com/supabase/edge-runtime/issues/334) wasn't supported, so the VAPID JWT failed        | June 2024    |
| Cloudflare Workers | [`https.request` wasn't implemented](https://github.com/cloudflare/workerd/issues/3820), so sends failed                               | August 2025  |
| Cloudflare Workers | [Request headers were sent as `ttl: TTL, 60`](https://github.com/cloudflare/workerd/issues/4880)                                       | August 2025  |
| Cloudflare Workers | [Requests to URLs with a query string were never sent](https://github.com/cloudflare/workerd/issues/5077), which Windows endpoints use | October 2025 |

### @pushforge/builder

[npm](https://www.npmjs.com/package/@pushforge/builder) · [GitHub](https://github.com/draphy/pushforge)

Builds the encrypted, signed request for you to send with any HTTP client. It still uses the draft `aesgcm` encryption, not RFC 8291's `aes128gcm`.

### @block65/webcrypto-web-push

[npm](https://www.npmjs.com/package/@block65/webcrypto-web-push) · [GitHub](https://github.com/block65/webcrypto-web-push)

Also builds the request for you to send. Since 2.0.0 it uses RFC 8291's `aes128gcm`, [tested against the RFC's example](https://github.com/block65/webcrypto-web-push/blob/master/packages/web-push/test/rfc8291.test.ts). It doesn't generate VAPID keys.

### web-push-neo

[npm](https://www.npmjs.com/package/web-push-neo) · [GitHub](https://github.com/ryoppippi/web-push-neo)

A TypeScript fork of `web-push` on `fetch` and Web Crypto that keeps its API, with `jose` as its one dependency. It handles errors the way `web-push` does.

### @negrel/webpush

[JSR](https://jsr.io/@negrel/webpush) · [GitHub](https://github.com/negrel/webpush)

Published on JSR only, for Deno, Workers, Bun and browsers. It treats a 410 as gone but not a 404, has no timeout, and its README says it "hasn't been reviewed by crypto experts".

</details>

| Package                       | Size, one send | Sends the request | Browser helpers | Sends to a list | Tested against RFC 8291's example |
| ----------------------------- | -------------- | ----------------- | --------------- | --------------- | --------------------------------- |
| **`@mmmike/web-push`**        | 3.0 kB         | ✓                 | ✓               | ✓               | ✓                                 |
| `web-push`                    | 35.3 kB + Node | ✓                 | ✗               | ✗               | ✗                                 |
| `@pushforge/builder`          | 2.6 kB         | ✗                 | ✗               | ✗               | ✗                                 |
| `@block65/webcrypto-web-push` | 2.2 kB         | ✗                 | ✗               | ✗               | ✓                                 |
| `web-push-neo`                | 7.8 kB         | ✓                 | ✗               | ✗               | ✗                                 |
| `@negrel/webpush`             | 5.0 kB         | ✓                 | ✗               | ✗               | ✗                                 |

Size is a minimal "send one notification" built with esbuild, minified and gzipped, on 23 October 2026. "+ Node" means it also needs Node's `crypto`, `https` and other built-in modules, which the figure leaves out.

## Which to use

- **On Node, with `web-push` already working:** it's the established choice and works well there. Switching gets you the browser helpers, sending to a list and the error handling, and drops 16 packages from your tree. The [migration guide](/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.
- **On Workers, Deno, Bun, Netlify or Supabase:** `web-push` runs on each runtime's emulation of Node and makes a Worker about ten times bigger. `@mmmike/web-push` runs on each one natively.
- **On Vercel Edge, or Workers with Node compatibility off:** `web-push` fails there, at build time or on its first send.
- **When you want only the request, to send through your own HTTP client:** `@block65/webcrypto-web-push` uses the standard encryption and tests it against the RFC. `@pushforge/builder` still uses the draft scheme.
