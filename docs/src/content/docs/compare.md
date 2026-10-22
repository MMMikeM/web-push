---
title: How it compares
description: How this package compares to web-push and the edge-native alternatives, and what running web-push off Node involves.
---

[`web-push`](https://www.npmjs.com/package/web-push) is the established choice, with ~5M weekly downloads and years in production. On Node it works well.

It is built on Node built-ins, `crypto.createECDH` for the key agreement and `https.request` for delivery, with no native Web Crypto or `fetch` path. On a non-Node runtime you are running a Node compatibility layer, and Cloudflare Workers is the clearest example.

## On Cloudflare Workers

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

With `nodejs_compat` and a current compatibility date, `web-push` does run on Workers ([issue #718, "Cloudflare Worker support?"](https://github.com/web-push-libs/web-push/issues/718), filed in 2022 and still open, tracks the history). That is Cloudflare's compatibility layer doing the work, which means:

- You carry the `nodejs_compat` flag and a compatibility date of 2024-09-23 or later.
- The polyfilled `node:https` and `node:crypto` stack ships in your bundle, against a Worker's size limit: measured on the same wrangler scaffold, `web-push` uploads 49.97 KiB gzipped where this package uploads about 3 KiB gzipped. It also brings 5 direct dependencies pulling in 16 packages.
- Your crypto runs through the `node:crypto` shim.
- It is Cloudflare's fix specifically. Bun and Deno ship their own Node compatibility layers, and `web-push` runs on those without setup, but it has no native Web Crypto or `fetch` path on any runtime.

## The client half

The other libraries compared here, `web-push` included, hand you a README snippet and have you call `pushManager.subscribe()` yourself. The call itself is five lines. The fiddly parts around it are the permission flow that starts from `"default"`, the base64url encoding of the application server key, and the serialisation your server actually stores, since `getKey()` returns an `ArrayBuffer`, which JSON can't hold. This package ships that half too, tested.

## Comparison

Competitor figures are as of 1.0.1's release, August 2026.

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

Neither edge-native alternative follows the ratified specs. Both encrypt with the draft-04 `aesgcm` scheme, putting the salt and DH key in `Encryption`/`Crypto-Key` headers instead of RFC 8291's binary header block, and one still authenticates with the pre-standard `Authorization: WebPush <jwt>`.

There's no dependency tree to audit here, the crypto is one file ([`src/encrypt.ts`](https://github.com/MMMikeM/web-push/blob/main/src/encrypt.ts)), and its output is pinned byte-for-byte against the test vector published in RFC 8291 itself.

[Migrating from `web-push`](/web-push/guides/migrate-from-web-push/) keeps your stored subscriptions, keys and service worker.
