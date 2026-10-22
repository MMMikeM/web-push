---
title: "@mmmike/web-push vs web-push and alternatives"
description: How @mmmike/web-push compares to web-push, @pushforge/builder, @block65/webcrypto-web-push, web-push-neo and @negrel/webpush, and what running web-push on Cloudflare Workers involves.
sidebar:
  label: How it compares
head:
  - tag: title
    content: "@mmmike/web-push vs web-push and alternatives"
---

[`web-push`](https://www.npmjs.com/package/web-push) is the established choice, with about 6.6 million weekly downloads and years in production. On Node it works well.

It is built on Node built-ins, `crypto.createECDH` for the key agreement and `https.request` for delivery, with no native Web Crypto or `fetch` path. On a non-Node runtime you are running a Node compatibility layer, and Cloudflare Workers is the clearest example.

## On Cloudflare Workers

`web-push` runs on Workers through Cloudflare's Node.js compatibility layer, and whether that layer is on depends on the Worker's compatibility date. [From 2026-08-04, `nodejs_compat` is on by default](https://developers.cloudflare.com/workers/configuration/compatibility-flags/), so a Worker created since then bundles `web-push` with no extra configuration. A Worker with an older compatibility date needs the flag, and without it hits the first error below.

### `Could not resolve "crypto"`

On a compatibility date before 2026-08-04 with no `nodejs_compat` flag, bundling fails with 28 module-resolution errors before workerd ever starts:

```text
✘ [ERROR] Could not resolve "crypto"

    node_modules/web-push/src/encryption-helper.js:3:23:
      3 │ const crypto = require('crypto');

  The package "crypto" wasn't found on the file system but is built into node.
  - Add the "nodejs_compat" compatibility flag to your project.
```

### `[unenv] https.request is not implemented yet!`

With the flag but a compatibility date before 2024-09-23, `web-push` has been seen to bundle cleanly and then fail at send time, from unenv's stubbed HTTP client:

```text
Error: [unenv] https.request is not implemented yet!
    at Object.fn [as request] (.../index.js:67:27)
    at WebPushLib.sendNotification (.../index.js:9347:14)
```

Wrangler 4.151.2 stops that setup earlier, at build time, with the same 28 module-resolution errors and a hint to prefix the imports with `node:` or move the compatibility date to 2024-09-23 or later.

### With Node compatibility on

From 2026-08-04 `nodejs_compat` is on by default, and before that it takes the flag and a compatibility date of 2024-09-23 or later. Either way, `web-push` does run on Workers ([issue #718, "Cloudflare Worker support?"](https://github.com/web-push-libs/web-push/issues/718), filed in 2022 and still open, tracks the history). That is Cloudflare's compatibility layer doing the work, which means:

- The polyfilled `node:https` and `node:crypto` stack ships in your bundle, against a Worker's size limit. For a minimal Worker that sends one notification, wrangler 4.151.2 reports a gzipped upload of 48.03 KiB with `web-push` 3.6.7 and 4.20 KiB with this package (36.08 KiB and 2.89 KiB with `--minify`). `web-push` also brings 5 direct dependencies, 16 packages in all.
- Your crypto runs through the `node:crypto` shim.
- Your Worker depends on the layer staying on. A compatibility date before 2026-08-04 needs the flag, and `no_nodejs_compat` turns it off.
- It is Cloudflare's fix specifically. Bun and Deno ship their own Node compatibility layers, and `web-push` runs on those without setup, but it has no native Web Crypto or `fetch` path on any runtime.

## The client half

None of the other libraries compared here, `web-push` included, ships browser code. They hand you a README snippet and have you call `pushManager.subscribe()` yourself. The call itself is five lines. The fiddly parts around it are the permission flow that starts from `"default"`, replacing a subscription made with an old VAPID key, and the serialisation your server actually stores, since `getKey()` returns an `ArrayBuffer`, which JSON can't hold. This package ships that half too, tested.

## Compared with web-push

Figures are as of 22 October 2026. Downloads are npm's count for the week of 12 to 18 October.

|                                   | `web-push`                                                                             | **`@mmmike/web-push`** |
| --------------------------------- | -------------------------------------------------------------------------------------- | ---------------------- |
| Node.js                           | ✓ 16+                                                                                  | ✓ 22.12+               |
| Bun and Deno                      | ✓ through their Node compatibility                                                     | ✓                      |
| Cloudflare Workers                | through `nodejs_compat` ([#718](https://github.com/web-push-libs/web-push/issues/718)) | ✓ without it           |
| Workers upload, gzipped           | 48.03 KiB                                                                              | 4.20 KiB               |
| Client subscribe helpers          | ✗                                                                                      | ✓                      |
| Sends the request                 | ✓ `https.request`                                                                      | ✓ `fetch`              |
| VAPID key generation              | ✓ synchronous, and a CLI                                                               | ✓ async                |
| RFC 8291 payload (`aes128gcm`)    | ✓, and draft `aesgcm` on request                                                       | ✓                      |
| RFC 8292 VAPID (`vapid t=…, k=…`) | ✓                                                                                      | ✓                      |
| Dependencies                      | 5 direct, 16 in all                                                                    | **zero**               |
| Licence                           | MPL-2.0                                                                                | MIT                    |
| Latest release                    | 3.6.7, January 2024                                                                    | 1.4.0, October 2026    |
| Weekly downloads                  | ~6.6M                                                                                  | ~9.3k                  |
| GitHub stars                      | 3.6k                                                                                   | 2                      |

## Compared with the edge-native libraries

These packages also use Web Crypto instead of `node:crypto`, so none of them needs Node compatibility on Workers. The runtimes listed are the ones each package names itself.

|                          | [`@pushforge/builder`](https://www.npmjs.com/package/@pushforge/builder) | [`@block65/webcrypto-web-push`](https://www.npmjs.com/package/@block65/webcrypto-web-push) | [`web-push-neo`](https://www.npmjs.com/package/web-push-neo) | [`@negrel/webpush`](https://jsr.io/@negrel/webpush) |
| ------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | --------------------------------------------------- |
| Runtimes it names        | Workers, Vercel Edge, Convex, Deno, Bun, Node 20+                        | Node, Workers, Bun, Deno                                                                   | Node, Deno, Bun, Workers                                     | Deno, Workers, Bun, browsers                        |
| Client subscribe helpers | ✗                                                                        | ✗                                                                                          | ✗                                                            | ✗                                                   |
| Sends the request        | ✗ builds it                                                              | ✗ builds it                                                                                | ✓ `fetch`                                                    | ✓ `fetch`                                           |
| VAPID key generation     | CLI only                                                                 | ✗                                                                                          | ✓                                                            | ✓ as a `CryptoKeyPair`                              |
| RFC 8291 (`aes128gcm`)   | ✗ draft `aesgcm`                                                         | ✓ since 2.0.0                                                                              | ✓                                                            | ✓                                                   |
| RFC 8292 VAPID           | ✓                                                                        | ✓ since 2.0.0                                                                              | ✓                                                            | ✓                                                   |
| Dependencies             | zero                                                                     | 1                                                                                          | 1 (`jose`)                                                   | 3, on JSR                                           |
| Licence                  | MIT                                                                      | MIT                                                                                        | MPL-2.0                                                      | MIT                                                 |
| Latest release           | 2.0.5, April 2026                                                        | 2.0.0, September 2026                                                                      | 0.1.2, March 2026                                            | 0.5.0, June 2025                                    |
| Weekly downloads         | ~52k                                                                     | ~73k                                                                                       | ~3.9k                                                        | JSR only                                            |
| GitHub stars             | 66                                                                       | 47                                                                                         | 11                                                           | 36                                                  |

Against the same rows, `@mmmike/web-push` names Workers, Deno, Bun, Node 22.12+ and browsers, ships the client helpers, sends with `fetch`, generates keys, follows both RFCs and has no dependencies.

`@pushforge/builder` still encrypts with the draft `aesgcm` scheme, putting the salt and DH key in `Encryption` and `Crypto-Key` headers instead of [RFC 8291's binary header block](https://www.rfc-editor.org/rfc/rfc8291#section-4). `@block65/webcrypto-web-push` moved to `aes128gcm` and the [RFC 8292 `vapid` scheme](https://www.rfc-editor.org/rfc/rfc8292#section-3) in 2.0.0, and its README says 1.x is the line to stay on if you need `aesgcm`. `web-push-neo` is a TypeScript fork of `web-push` that keeps its API shape and takes VAPID details on each call. `@negrel/webpush` is published on JSR only, where its maintainer leaves Node off the list of supported runtimes, and its README says it "hasn't been reviewed by crypto experts".

There's no dependency tree to audit here, the crypto is one file ([`src/encrypt.ts`](https://github.com/MMMikeM/web-push/blob/main/src/encrypt.ts)), and [a test](https://github.com/MMMikeM/web-push/blob/main/test/rfc8291-vector.test.ts) pins its output byte-for-byte to the [test vector in RFC 8291's Appendix A](https://www.rfc-editor.org/rfc/rfc8291#appendix-A).

[Migrating from `web-push`](/web-push/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.
