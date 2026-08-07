# web-push

Zero-dependency Web Push (RFC 8291) for Workers, Deno, Bun, Vercel Edge, Node 22.12+, and browsers.

## Hard constraints

- **No runtime dependencies.** Ever. `devDependencies` only.
- **Web Crypto only.** No `node:` imports in `src/` — they break every non-Node target. `tsconfig.check.json` sets `types: []` to make that a compile error rather than a runtime surprise.
- **Erasable syntax in `scripts/`.** Those run as `node scripts/foo.ts` via type stripping. No enums, namespaces, or parameter properties; `tsconfig.tools.json` enforces it.

## Commands

`pnpm run check` is the gate: `format:check` → `lint` → `lint:types` → `test` → `audit`. Run it before claiming done. `pnpm run check:package` additionally builds and validates the exports map.

## Documentation

**Every exported function, class, and type in `src/` carries JSDoc.** Re-export statements (`export type { X } from "./y"`) don't.

JSDoc says what the caller needs and nothing more:

- Lead with what it does, in one line.
- `@param` only when the name and type don't already say it — skip `@param subscription The subscription`.
- `@throws` whenever it can throw. Callers can't see that from the signature.
- `@example` on primary entry points only (`sendPushNotification`, `subscribeToPush`, `generateVapidKeys`).
- Never restate the type signature in prose. TypeScript already published it.

## Comments

**Default to none.** A comment is a cost: it can go stale, and it's evidence the code didn't explain itself. Reach for a better name or a small extracted function first — a well-named `deriveContentEncryptionKey()` beats five lines narrating an HKDF chain.

Delete comments that restate the code:

```ts
// Add padding if needed                                    ← says nothing the next line doesn't
const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
```

**Extract unclear logic into functions that explain it.** A comment labelling a
block of code is that block asking to be a function. The name then survives
refactoring, gets typechecked, and appears at the call site — three things a
comment can't do.

```ts
// Build the aes128gcm content-coding header
// Format: salt (16) + rs (4) + idlen (1) + keyid (65) + ciphertext
const header = new Uint8Array(HEADER_LENGTH);
header.set(salt, 0); // Salt
new DataView(header.buffer).setUint32(16, RECORD_SIZE, false); // Record size (big endian)
header[20] = 65; // Key ID length
header.set(serverPublicKey, 21); // Key ID (server ephemeral public key)

// Combine header and ciphertext
const body = new Uint8Array(header.length + ciphertext.byteLength);
body.set(header);
body.set(new Uint8Array(ciphertext), header.length);
```

becomes one line, with the spec citation kept as JSDoc on the extracted function:

```ts
const body = concat(contentCodingHeader(salt, serverPublicKey), new Uint8Array(ciphertext));
```

Applies hardest to long procedural functions — a crypto or protocol routine with
six labelled steps is six named functions and a readable body. The step comments
disappear because the names replaced them; the `@see RFC` notes stay, because
those the code genuinely cannot carry.

Write comments only for what the code genuinely cannot carry:

- **Spec citations.** `// RFC 8188 §2.1: salt | rs | idlen | keyid` — the magic numbers are meaningless without it.
- **Why, when the why is surprising.** `test/helpers.ts` re-implements the receiver side instead of calling `src/` — without that note someone "deduplicates" it and destroys the cross-check.
- **Toolchain and protocol landmines** that look like mistakes and get "fixed" back: the `Uint8Array<ArrayBuffer>` annotation on `concat`, the unused `_input`/`_init` params that give mocks a non-empty call tuple.
- **Security-relevant invariants** — why a bound exists, what breaks without it.

Keep them to a sentence or two. If a comment needs a paragraph, that's usually a signal the design needs the work, not the prose. Config files (`pnpm-workspace.yaml`, workflows) earn slightly more latitude, since YAML has nowhere else to record intent — but the same ceiling applies.

Never add comments that narrate a change (`// now uses X`, `// fixed to handle Y`). That belongs in the commit message; the code is the current state.

A file header is not exempt — it is a comment, held to the same test. "What is this
file" is the filename's job, and "what does it export" is the exports' job; neither
earns a header. Write one only for what reading the file cannot tell you: that
`client.ts` throws outside a browser, that `encrypt.ts` is deliberately not an entry
point, that `test/helpers.ts` duplicates the library on purpose. Most files should
open on their first import.

## Tests

Vitest, `test/**/*.test.ts`. Tests are typechecked — `tsconfig.check.json` covers them, so mocks need real parameter types rather than casts asserting over an empty tuple.

Name tests as behaviour, not method (`"keeps the VAPID JWT expiry within 24h even for a long message ttl"`). Prefer a failing assertion that reads as a spec sentence over a comment explaining what the assertion means.

## Style

Enforced by oxfmt/oxlint, not by hand: tabs, double quotes, semicolons, 100 columns. Run `pnpm run format`.
