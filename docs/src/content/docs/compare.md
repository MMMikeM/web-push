---
title: "@mmmike/web-push vs web-push and alternatives"
description: How @mmmike/web-push compares to web-push, PushForge, block65 and the other edge-native packages, and why it runs on fetch and Web Crypto instead of Node.
sidebar:
  label: How it compares
head:
  - tag: title
    content: "@mmmike/web-push vs web-push and alternatives"
---

`@mmmike/web-push` and [`web-push`](https://www.npmjs.com/package/web-push) are separate packages by different authors. `web-push` is the [web-push-libs](https://github.com/web-push-libs/web-push) Node library, on npm since 2015 and the one most Web Push tutorials use. `@mmmike/web-push` is a newer package that shares no code with it.

Both send the same standard notifications. `web-push` is built on Node's `crypto` and `https` modules, and `@mmmike/web-push` on `fetch` and Web Crypto, which Cloudflare Workers, Deno, Bun, Node and browsers each implement natively. Subscriptions and VAPID keys work with either, so switching keeps the ones you've stored.

## At a glance

| Package                                                                                    | Node APIs | Sends | Browser helpers | Encryption            | Deps  |
| ------------------------------------------------------------------------------------------ | --------- | ----- | --------------- | --------------------- | ----- |
| **`@mmmike/web-push`**                                                                     | none      | ✓     | ✓               | `aes128gcm`           | **0** |
| [`web-push`](https://www.npmjs.com/package/web-push)                                       | required  | ✓     | ✗               | `aes128gcm`, `aesgcm` | 16    |
| [`@pushforge/builder`](https://www.npmjs.com/package/@pushforge/builder)                   | none      | ✗     | ✗               | draft `aesgcm`        | 0     |
| [`@block65/webcrypto-web-push`](https://www.npmjs.com/package/@block65/webcrypto-web-push) | none      | ✗     | ✗               | `aes128gcm`           | 1     |
| [`web-push-neo`](https://www.npmjs.com/package/web-push-neo)                               | none      | ✓     | ✗               | `aes128gcm`           | 1     |
| [`@negrel/webpush`](https://jsr.io/@negrel/webpush)                                        | none      | ✓     | ✗               | `aes128gcm`           | 3     |

"Sends" means the package makes the request itself; the two without it build the request for you to send. Figures are as of 22 October 2026.

## Which to use

- **On Node, with `web-push` already working:** it's the established choice and works well there. Switching gets you the browser helpers, batches and the error model, and drops 16 packages from your tree. The [migration guide](/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.
- **On Workers, Deno, Bun, Netlify or Supabase:** `web-push` runs on each runtime's emulation of Node, and this package needs none. [Why that matters](/compare/#why-node-emulation-matters) is below.
- **On Vercel Edge, or Workers with Node compatibility off:** `web-push` doesn't run there; this package does.
- **Choosing between the Web Crypto packages:** two of them only build the request for you to send, none has browser helpers or batches, and `@pushforge/builder` still uses the draft `aesgcm` encryption. There are [notes on each](/compare/#the-other-packages) at the end.

## Coming from web-push

Downloads are npm's count for the week of 12 to 18 October 2026.

|                           | **`@mmmike/web-push`**                                                                                                      | `web-push`                                        |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Built on                  | `fetch` and Web Crypto                                                                                                      | Node's `crypto` and `https`                       |
| Dependencies              | **zero**                                                                                                                    | 5 direct, 16 in all                               |
| Browser subscribe helpers | ✓                                                                                                                           | ✗                                                 |
| Sending to many           | `sendPushBatch`, bounded concurrency                                                                                        | ✗, one call per subscription                      |
| Gone subscriptions        | resolve `false`, listed under `gone`                                                                                        | throw `WebPushError` with status 404 or 410       |
| `Retry-After`             | parsed to `retryAfterMs`                                                                                                    | in the error's headers                            |
| Timeout and cancellation  | 30 s default timeout, `AbortSignal`                                                                                         | optional socket timeout                           |
| Runtimes                  | Node 22.12+, Workers, Deno, Bun, browsers                                                                                   | Node 16+, and others through their Node emulation |
| RFC 8291 payload          | ✓ `aes128gcm`, [tested against the RFC's vector](https://github.com/MMMikeM/web-push/blob/main/test/rfc8291-vector.test.ts) | ✓ `aes128gcm`, and draft `aesgcm` on request      |
| RFC 8292 VAPID            | ✓                                                                                                                           | ✓                                                 |
| VAPID key generation      | ✓ async                                                                                                                     | ✓ synchronous, and a CLI                          |
| Licence                   | MIT                                                                                                                         | MPL-2.0                                           |
| Latest release            | 1.4.2, October 2026                                                                                                         | 3.6.7, January 2024                               |
| Weekly downloads          | ~9.3k                                                                                                                       | ~6.6M                                             |
| GitHub stars              | 2                                                                                                                           | 3.6k                                              |

## Why Node emulation matters

Outside Node, `web-push` runs because the runtime emulates Node's `crypto` and `https` modules. On Cloudflare Workers that makes a much larger Worker, on Vercel Edge it fails, and on several runtimes the emulation has broken it before being fixed.

### On Cloudflare Workers

From the [2026-08-04 compatibility date](https://developers.cloudflare.com/workers/configuration/compatibility-flags/), Workers turn on `nodejs_compat` by default, so `web-push` builds in a new Worker with no configuration. Measured on a minimal Worker that sends one notification, with wrangler 4.151.2 and a 2026-10-01 compatibility date:

|                           | `web-push` 3.6.7           | `@mmmike/web-push` 1.4.0 | Empty Worker |
| ------------------------- | -------------------------- | ------------------------ | ------------ |
| Upload                    | 252.96 KiB                 | 13.27 KiB                | 0.16 KiB     |
| Upload, gzipped           | 48.03 KiB                  | 4.20 KiB                 | —            |
| Startup, measured locally | 22.5 ms                    | 8.6 ms                   | 9.1 ms       |
| With `no_nodejs_compat`   | fails to build (28 errors) | builds, 4.21 KiB gzipped | —            |

The difference is `web-push`'s dependency tree (bn.js, asn1.js, jws, http_ece and others). Node compatibility itself adds nothing to a Worker that doesn't import Node modules, and this package's Worker is the same size with it on or off. Both are far inside Cloudflare's limits, and once loaded, encrypting and signing a message takes about the same time with either. The startup figures come from `wrangler check startup` on an M-series Mac; Cloudflare's machines differ.

### On Vercel Edge

Vercel's Edge runtime supports only a few Node modules, and `crypto` isn't one of them. A Next.js route with `runtime = "edge"` builds with `web-push` and then fails on the first send with `The edge runtime does not support Node.js 'crypto' module`; the same route sends with this package. Vercel now [recommends its Node.js runtime](https://vercel.com/docs/functions/runtimes/edge), where `web-push` works, and Next.js 16.3 dropped `runtime = "edge"` for route handlers.

### When the emulation broke

Each of these broke `web-push` until the runtime fixed it:

| Runtime            | What broke                                                                                                                             | Until        |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| Deno               | [Chrome couldn't decrypt the payloads](https://github.com/denoland/deno/issues/23693), so notifications never arrived                  | August 2024  |
| Supabase           | [Signing with an EC private key](https://github.com/supabase/edge-runtime/issues/334) wasn't supported, so the VAPID JWT failed        | June 2024    |
| Cloudflare Workers | [`https.request` wasn't implemented](https://github.com/cloudflare/workerd/issues/3820), so sends failed                               | August 2025  |
| Cloudflare Workers | [Request headers were sent as `ttl: TTL, 60`](https://github.com/cloudflare/workerd/issues/4880)                                       | August 2025  |
| Cloudflare Workers | [Requests to URLs with a query string were never sent](https://github.com/cloudflare/workerd/issues/5077), which Windows endpoints use | October 2025 |

On Workers, `web-push`'s `proxy` option still throws. This package calls `fetch` and `crypto.subtle`, which each runtime implements itself, so a gap in a runtime's Node emulation doesn't reach it.

### Older Workers compatibility dates

Before 2024-09-23, or on any date before 2026-08-04 without the `nodejs_compat` flag, `web-push` fails to build with 28 errors like this one:

```text
✘ [ERROR] Could not resolve "crypto"

    node_modules/web-push/src/encryption-helper.js:3:23:
      3 │ const crypto = require('crypto');

  The package "crypto" wasn't found on the file system but is built into node.
  - Add the "nodejs_compat" compatibility flag to your project.
```

From 2024-09-23 to 2025-08-14 with the flag, it builds and then fails on the first send:

```text
Error: [unenv] https.request is not implemented yet!
```

This package builds and sends on any compatibility date, with or without the flag.

## The other packages

| Package                       | Latest release        | Weekly downloads | Licence |
| ----------------------------- | --------------------- | ---------------- | ------- |
| `@pushforge/builder`          | 2.0.5, April 2026     | ~52k             | MIT     |
| `@block65/webcrypto-web-push` | 2.0.0, September 2026 | ~73k             | MIT     |
| `web-push-neo`                | 0.1.2, March 2026     | ~3.9k            | MPL-2.0 |
| `@negrel/webpush`             | 0.5.0, June 2025      | JSR only         | MIT     |

- **`@pushforge/builder`** encrypts with the draft `aesgcm` scheme, putting the salt and DH key in `Encryption` and `Crypto-Key` headers instead of [RFC 8291's binary header block](https://www.rfc-editor.org/rfc/rfc8291#section-4). It generates VAPID keys from its CLI only, and names Workers, Vercel Edge, Convex, Deno, Bun and Node 20+ as its runtimes.
- **`@block65/webcrypto-web-push`** moved to `aes128gcm` and the [RFC 8292 `vapid` scheme](https://www.rfc-editor.org/rfc/rfc8292#section-3) in 2.0.0; its README says to stay on 1.x if you need `aesgcm`. It doesn't generate VAPID keys.
- **`web-push-neo`** is a TypeScript fork of `web-push` that keeps its API, with `jose` as its one dependency.
- **`@negrel/webpush`** is published on JSR only. Its maintainer names Deno, Workers, Bun and browsers as its runtimes, leaving Node off, and its README says it "hasn't been reviewed by crypto experts". It returns VAPID keys as a `CryptoKeyPair`.
