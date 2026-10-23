# web-push

Zero-dependency Web Push (RFC 8291) for Workers, Deno, Bun, Vercel Edge, Node 22.12+, and browsers.

## Hard constraints

- **No runtime dependencies.** Ever. `devDependencies` only.
- **Web Crypto only.** No `node:` imports in `src/` — they break every non-Node target. `tsconfig.check.json` sets `types: []` to make that a compile error rather than a runtime surprise.
- **Erasable syntax in `scripts/`.** Those run as `node scripts/foo.ts` via type stripping. No enums, namespaces, or parameter properties; `tsconfig.tools.json` enforces it.

## Commands

`pnpm run check` is the gate: `format:check` → `lint` → `lint:types` → `coverage` → `audit`. Run it before claiming done. Coverage of `src/` must stay at 100%: a new branch needs a test. `pnpm run check:package` additionally builds and validates the exports map.

## Docs site

`docs/` is an Astro Starlight site, a separate project with its own `pnpm-workspace.yaml` and lockfile, so its dependencies never reach the library's lockfile or the `audit` in its release gate. Install and build from inside it (`pnpm --dir docs build`). The root formatter covers it, except the generated reference pages.

- **The API reference is generated, not written.** `docs/scripts/generate-reference.ts` reads `src/` through TypeScript 7.1's API (a beta, hence the release-age exclusions in `docs/pnpm-workspace.yaml`) and writes `src/content/docs/reference/`, which is gitignored. Change the JSDoc, not the output.
- **The build fails on an export without JSDoc**, and `scripts/check-dist.ts` fails it on a built page missing its canonical, metadata, JSON-LD or Markdown copy.
- **The tutorial shows `examples/app` as it is.** `tutorial.mdx` imports the example's files with `?raw`, so changing the example changes the tutorial; keep its prose in step.
- **`ai-agents.md` ships in the package.** `scripts/agents-md.ts` builds `dist/AGENTS.md` during `vp pack` from the page's sections (everything from its first `##`) and the built entry points, so a rule changed there changes what every install reads.
- **The home page's push demo needs two Worker secrets.** `docs/worker/push-demo.ts` sends one fixed notification to a subscription the page posts, using `DEMO_VAPID_PUBLIC_KEY` and `DEMO_VAPID_PRIVATE_KEY`. `node docs/scripts/push-demo-keys.ts` sets both; locally, `docs/.dev.vars` holds a throwaway pair.
- **Links are root-absolute: `/guides/handle-errors/`, never `../handle-errors/`.** The same Markdown is served per page (`<page>.md`) and bundled into `llms-full.txt`, where relative links resolve against the wrong URL.
- **It deploys to a Cloudflare Worker at `web-push.thelazyweb.dev`**, from `docs.yml` once `release.yml` has published a stable release. `docs/worker/` serves each page's Markdown copy to requests that send `Accept: text/markdown`.

## Runtime conformance

`e2e/` is its own pnpm root too, for wrangler and anything else a cross-runtime test needs. `e2e/conformance/checks.ts` runs the built package (`pnpm run build` first) through RFC 8291's test vector, decryption by `test/receiver.ts`, VAPID JWT verification and send results. `conformance.yml` runs it on Node 22.12 (the `engines` floor), the latest 22 and 24, Deno, Bun and workerd, from `ci.yml` on every push and from `release.yml`, which publishes only if it passes (`pnpm --dir e2e run conformance:<runtime>` locally). `e2e/browsers/deliver.ts` subscribes in Chrome and Firefox and sends through their real push services; `chrome.yml` and `firefox.yml` run it through `browsers.yml` on every push and pull request, and daily, one workflow per browser so each has its own README badge.

- **`test/receiver.ts` imports nothing and uses only Web APIs**, so every runtime can load it. Keep vitest and `src/` out of it.

## Documentation

**Every exported function, class, and type in `src/` carries JSDoc.** Re-export statements (`export type { X } from "./y"`) don't. **So does every field of an exported object type**: the reference renders each one as a table row, and an undocumented field is an empty cell.

JSDoc says what the caller needs and nothing more:

- Lead with what it does, in one line.
- `@param` only when the name and type don't already say it — skip `@param subscription The subscription`. A parameter typed by one of the library's own types borrows that type's summary in the reference.
- `@returns` when the return type alone doesn't say what the values mean, such as the strings of a browser type like `NotificationPermission`.
- `@throws` whenever it can throw. Callers can't see that from the signature.
- `@example` on primary entry points only (`sendPushNotification`, `sendPushBatch`, `subscribe`, `generateVapidKeys`).
- `{@link name}` to refer to another export. The reference turns it into a link; backticks stay plain code.
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
- **Why, when the why is surprising.** `test/receiver.ts` re-implements the receiver side instead of calling `src/` — without that note someone "deduplicates" it and destroys the cross-check.
- **Toolchain and protocol landmines** that look like mistakes and get "fixed" back: the `Uint8Array<ArrayBuffer>` annotation on `concat`, the explicit `vi.fn<...>()` type parameters that give mocks a non-empty call tuple.
- **Security-relevant invariants** — why a bound exists, what breaks without it.

Keep them to a sentence or two. If a comment needs a paragraph, that's usually a signal the design needs the work, not the prose. Config files (`pnpm-workspace.yaml`, workflows) earn slightly more latitude, since YAML has nowhere else to record intent — but the same ceiling applies.

Never add comments that narrate a change (`// now uses X`, `// fixed to handle Y`). That belongs in the commit message; the code is the current state.

A file header is not exempt — it is a comment, held to the same test. "What is this
file" is the filename's job, and "what does it export" is the exports' job; neither
earns a header. Write one only for what reading the file cannot tell you: that
`client.ts` throws outside a browser, that `encrypt.ts` is deliberately not an entry
point, that `test/receiver.ts` duplicates the library on purpose. Most files should
open on their first import.

## Tests

Vitest, `test/**/*.test.ts`. Tests are typechecked — `tsconfig.check.json` covers them, so mocks need real parameter types rather than casts asserting over an empty tuple.

Name tests as behaviour, not method (`"keeps the VAPID JWT expiry within 24h even for a long message ttl"`). Prefer a failing assertion that reads as a spec sentence over a comment explaining what the assertion means.

## Style

Enforced by oxfmt/oxlint, not by hand: tabs, double quotes, semicolons, 100 columns. Run `pnpm run format`.
