# Changelog

All notable changes to `@mmmike/web-push` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-12

First stable release, and the first with a test suite. The library gained validation,
structured errors, and standards-compliance tests; a few real bugs surfaced and were
fixed along the way. Breaking changes are called out under **Changed**; with the API
now settled and tested, this ships as stable so those breaks cost a major bump rather
than hiding under a pre-1.0 minor.

### Added

- **`sendPushBatch`** — send one notification to many subscriptions through a worker
  pool with bounded concurrency (default 100). Resolves to
  `{ delivered, gone, failed }` instead of throwing mid-batch: `delivered` counts
  accepted sends, `gone` lists the endpoints to delete (404/410), `failed` carries
  each undelivered send with its error. Caller-input mistakes (bad VAPID config,
  oversized payload, invalid topic) still throw, before anything is sent. Signs one
  VAPID JWT per push-service origin rather than one per message — the token is
  origin-scoped, so a batch of ten thousand costs a handful of ES256 signatures
  instead of ten thousand.
- **`SendPushOptions.signal` and `SendPushOptions.timeoutMs`** (default 30s) —
  every request carries an abort signal, so a push service that accepts the
  connection and never responds releases its pool slot instead of holding it for
  the platform's limit. Aborting `signal` also stops a batch from starting new
  sends.
- **Test suite (Vitest).** 134 tests across the codec, VAPID key generation and JWT
  signing, aes128gcm encryption, and the browser client flow, including an
  independent round-trip decrypt, the RFC 8291 Appendix A known-answer vector,
  ES256 verification of the actual `Authorization` JWT, and random-input sweeps
  over the codec lengths and payload-size boundaries. 100% line/branch/function
  coverage. New scripts: `test`, `test:watch`, `coverage`.
- **`WebPushError`** (exported) carrying `statusCode`, `body`, `endpoint`,
  `retryAfter` (the header verbatim), and `retryAfterMs` (parsed to milliseconds
  from now, whether the service sent delta-seconds or an HTTP-date), thrown on
  rate limits and other push-service errors so callers can back off and log.
- **`SendPushOptions.vapidExpiration`** (default `43200` / 12h) controls the VAPID
  JWT lifetime independently of the message `ttl`.
- **`SendPushOptions.urgency`** (`very-low` | `low` | `normal` | `high`) and
  **`SendPushOptions.topic`** (collapse key) emit the `Urgency` and `Topic` headers
  (RFC 8030).
- **Input validation with clear errors** for: VAPID subject (`mailto:`/`https:`),
  VAPID public key (65-byte `0x04` point) and private key (32-byte scalar),
  subscription `p256dh` (65-byte `0x04` point) and `auth` (≥16 bytes), `topic`
  (≤32 URL-safe base64 chars), and oversized payloads (see Bug C). On the client,
  `serializeSubscription` now throws `Subscription is missing its p256dh key` (or
  `auth`) instead of crashing on a null dereference.
- **Packaging:** `sideEffects: false`, `publint` + `@arethetypeswrong/cli` checks
  gating publish, and tag-driven releases published with npm provenance. (Format and
  Node floor are under **Changed**: ESM-only, `>=22.12`.)

### Changed

- **`subscribeToPush` now resolves to a `SubscribeResult`** (breaking) — the exported
  discriminated union `{ status: "subscribed", subscription, isNew }`,
  `{ status: "unsupported" }`, or `{ status: "denied" }` — instead of
  `PushSubscription | null`. The `null` return conflated "this browser can't do push"
  with "the user said no", and nothing told the caller whether the subscription still
  needed uploading; `isNew` now carries that. The `console.warn` calls on the failure
  paths are gone with it.
- **`subscribeToPush` rotates a subscription bound to a different VAPID key**
  (breaking) instead of returning it. A subscription created under a retired key is
  rejected by the push service on every send, so the old one is unsubscribed and
  replaced, and the result is flagged `isNew: true`. Browsers that don't report
  `options.applicationServerKey` keep their existing subscription.
- **The package is now ESM-only.** Shipping both formats meant two copies of
  `WebPushError` could coexist in one dependency tree, silently breaking
  `instanceof` against it, the only way to tell a push-service rejection from a
  malformed request, and what the Worker example uses. Node 22.12+ can `require()`
  ESM directly, so CJS consumers keep working.
- **Minimum Node version is now 22.12.** Node 18 and 20 have both reached end of
  life, the codebase targets the ES2023 library, and 22.12 is where `require(esm)`
  landed. Non-Node runtimes (Workers, Deno, Bun, Vercel Edge, browsers) are
  unaffected.
- **VAPID JWT expiry is now decoupled from `ttl`.** Previously the JWT `exp` was set
  to the message `ttl` (defaulting to 24h); it now defaults to 12h via
  `vapidExpiration`, and `ttl` drives only the `TTL` header. See Bug B.
- **`createVapidJwt` validates the expiration range** and throws outside 1–86400
  seconds: the RFC 8292 24-hour maximum on one side, zero and negative values on the
  other.
- **Rate-limit (429) and other non-2xx responses now throw `WebPushError`** instead of
  a generic `Error`. Still `instanceof Error`; messages are unchanged. `404`/`410`
  continue to resolve to `false`.
- **VAPID `subject` is now validated and rejected when malformed** (breaking). It must
  be a `mailto:` or `https:` URI; previously any string was forwarded untouched.
  Callers that passed a bare email address or an `http:` contact URL now get a thrown
  `Error` at send time instead of a request the push service would `401`. This is a
  fail-fast correctness fix, but it can break code that leaned on the old pass-through.
- **Internal structure:** the aes128gcm crypto core moved to `src/encrypt.ts` (kept
  out of the public API); ambiguous local names were clarified (the application-server
  ephemeral key, `ciphertext`, `body`); base64 encoding is now chunked.
- **README:** `PushPayload` documentation corrected to the actual shape
  (`title`, `body`, `url?`, `tag?`) and the new options + `WebPushError` documented.

### Fixed

- **Bug A - base64 stack overflow.** `uint8ArrayToUrlBase64` (and the client's
  `arrayBufferToUrlBase64`) used `String.fromCharCode(...array)`, which threw
  `RangeError: Maximum call stack size exceeded` on large inputs. Now encoded in
  chunks. (Latent in practice, only small keys flowed through it, but fixed and
  regression-tested.)
- **Bug B - VAPID token rejected for long TTLs.** Because the JWT `exp` was the message
  `ttl`, any `ttl` beyond 24h produced a token push services reject with `401`. For
  scale: the canonical `web-push` library defaults every send's `TTL` to four weeks
  (`2419200`), so a send loop carrying that habit into this package would have failed
  every time. Fixed by decoupling and capping (above).
- **Bug C - oversized payloads exceeded the push-service body limit.** Nothing
  rejected a plaintext large enough to push the encrypted request body past the
  4096-octet limit a push service must accept (RFC 8291 §4). Now throws a
  descriptive error when the payload exceeds **3993 bytes**, the true ceiling:
  a 4096-octet body minus the 86-byte aes128gcm header, the 1-byte padding
  delimiter, and the 16-byte GCM tag.
- **Bug D - `unsubscribeFromPush` crashed on unsupported browsers.** It reached for
  `navigator.serviceWorker.ready` without a support check, so where push is
  unavailable it rejected with a `TypeError` instead of resolving a boolean. It now
  resolves `true` (nothing to unsubscribe from), matching `subscribeToPush` and
  `getCurrentSubscription`, which already guarded.

### Security

- The RFC 8291 Appendix A known-answer test pins the encryption output byte-for-byte
  against the specification, guarding the key schedule (HKDF `info` strings, byte
  order, padding delimiter, header layout) against silent regressions.

## [0.1.0] - 2025-12-30

- Initial release: zero-dependency Web Push (RFC 8291 aes128gcm + RFC 8292 VAPID) for
  Cloudflare Workers, Deno, Bun, Vercel Edge, Node.js, and browsers, built on the Web
  Crypto API. Client subscription helpers, server-side send, and VAPID key generation
  via subpath exports.
