# Web Push from a Cloudflare Worker

A minimal, deployable Worker that sends Web Push notifications with
[`@mmmike/web-push`](https://www.npmjs.com/package/@mmmike/web-push) — **zero
dependencies, Web Crypto only, no `nodejs_compat` flag**.

The `web-push` npm package can't run here — it calls `crypto.createECDH` and
`https.request`, which don't exist in the Workers runtime
([issue #718](https://github.com/web-push-libs/web-push/issues/718)). This one
uses only `crypto.subtle` and `fetch`, so it runs unchanged on the edge.

## Setup

```bash
npm install

# 1. Generate a VAPID key pair
npm run keys

# 2. Load the keys as Worker secrets
npx wrangler secret put VAPID_PUBLIC_KEY
npx wrangler secret put VAPID_PRIVATE_KEY
npx wrangler secret put VAPID_SUBJECT      # e.g. mailto:you@example.com

# 3. Run locally, then deploy
npm run dev
npm run deploy
```

## Routes

| Method | Path                | Purpose                                               |
| ------ | ------------------- | ----------------------------------------------------- |
| `GET`  | `/vapid-public-key` | Returns the public key the browser needs to subscribe |
| `POST` | `/send`             | Body `{ subscription, payload }` — sends one push     |

## Send a test push

`subscription` is what the browser produces via
[`subscribeToPush()`](https://www.npmjs.com/package/@mmmike/web-push) on the
client and POSTs to your server.

```bash
curl -X POST https://<your-worker>.workers.dev/send \
  -H 'content-type: application/json' \
  -d '{
    "subscription": { "endpoint": "https://fcm.googleapis.com/...", "keys": { "p256dh": "...", "auth": "..." } },
    "payload": { "title": "Hello from the edge", "body": "Sent by a Cloudflare Worker" }
  }'
```

`{ "delivered": true }` on success. `{ "delivered": false }` means the push
service returned 404/410 — the subscription is dead, delete it from your store.
