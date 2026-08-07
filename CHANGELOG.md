# Changelog

All notable changes to `@mmmike/web-push` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — Unreleased

First stable release, and the first with a test suite. The library gained validation,
structured errors, and standards-compliance tests; a few real bugs surfaced and were
fixed along the way. Breaking changes are called out under **Changed** — with the API
now settled and tested, this ships as `1.0.0` so those breaks cost a major bump rather
than hiding under a pre-1.0 minor.

### Added

- **Test suite (Vitest).** 75 tests across the codec, VAPID key generation and JWT
  signing, aes128gcm encryption, and the browser client flow — including an
  independent round-trip decrypt and the RFC 8291 Appendix A known-answer vector.
  100% line/branch/function coverage. New scripts: `test`, `test:watch`, `coverage`.
- **`WebPushError`** (exported) carrying `statusCode`, `body`, `endpoint`, and
  `retryAfter`, thrown on rate limits and other push-service errors so callers can
  back off and log.
- **`SendPushOptions.vapidExpiration`** (default `43200` / 12h) — controls the VAPID
  JWT lifetime independently of the message `ttl`.
- **`SendPushOptions.urgency`** (`very-low` | `low` | `normal` | `high`) and
  **`SendPushOptions.topic`** (collapse key) — emit the `Urgency` and `Topic` headers
  (RFC 8030).
- **Input validation with clear errors** for: VAPID subject (`mailto:`/`https:`),
  VAPID public key (65-byte `0x04` point) and private key (32-byte scalar),
  subscription `p256dh` (65-byte `0x04` point) and `auth` (≥16 bytes), `topic`
  (≤32 URL-safe base64 chars), and oversized payloads (see Bug C).
- **Packaging:** dual ESM + CJS output, `sideEffects: false`, `engines: node >=18`,
  and `publint` + `@arethetypeswrong/cli` checks gating publish.

### Changed

- **The package is now ESM-only.** Shipping both formats meant two copies of
  `WebPushError` could coexist in one dependency tree, silently breaking
  `instanceof` against it — the only way to tell a push-service rejection from a
  malformed request, and what the Worker example uses. Node 22.12+ can `require()`
  ESM directly, so CJS consumers keep working.
- **Minimum Node version is now 22.12.** Node 18 and 20 have both reached end of
  life, the codebase targets the ES2023 library, and 22.12 is where `require(esm)`
  landed. Non-Node runtimes (Workers, Deno, Bun, Vercel Edge, browsers) are
  unaffected.
- **VAPID JWT expiry is now decoupled from `ttl`.** Previously the JWT `exp` was set
  to the message `ttl` (defaulting to 24h); it now defaults to 12h via
  `vapidExpiration`, and `ttl` drives only the `TTL` header. See Bug B.
- **`createVapidJwt` enforces the RFC 8292 24-hour maximum** on expiration and throws
  otherwise.
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

- **Bug A — base64 stack overflow.** `uint8ArrayToUrlBase64` (and the client's
  `arrayBufferToUrlBase64`) used `String.fromCharCode(...array)`, which threw
  `RangeError: Maximum call stack size exceeded` on large inputs. Now encoded in
  chunks. (Latent in practice — only small keys flowed through it — but fixed and
  regression-tested.)
- **Bug B — VAPID token rejected for long TTLs.** Because the JWT `exp` was the message
  `ttl`, any `ttl` beyond 24h produced a token push services reject with `401`. Fixed
  by decoupling and capping (above).
- **Bug C — oversized payloads exceeded the push-service body limit.** Nothing
  rejected a plaintext large enough to push the encrypted request body past the
  4096-octet limit a push service must accept (RFC 8291 §4). Now throws a
  descriptive error when the payload exceeds **3993 bytes** — the true ceiling:
  a 4096-octet body minus the 86-byte aes128gcm header, the 1-byte padding
  delimiter, and the 16-byte GCM tag.

### Security

- The RFC 8291 Appendix A known-answer test pins the encryption output byte-for-byte
  against the specification, guarding the key schedule (HKDF `info` strings, byte
  order, padding delimiter, header layout) against silent regressions.

## [0.1.0] — 2025-12-30

- Initial release: zero-dependency Web Push (RFC 8291 aes128gcm + RFC 8292 VAPID) for
  Cloudflare Workers, Deno, Bun, Vercel Edge, Node.js, and browsers, built on the Web
  Crypto API. Client subscription helpers, server-side send, and VAPID key generation
  via subpath exports.
