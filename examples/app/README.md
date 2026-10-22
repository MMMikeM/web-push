# Web Push example app

A page with a notifications toggle, a server that stores subscriptions, and a route that pushes to every subscriber. The server is one fetch handler (`src/app.ts`) with an entry point per runtime: Node (`src/node.ts`), Bun (`src/bun.ts`), Deno (`src/deno.ts`), and Cloudflare Workers (`src/worker.ts`).

The [tutorial](https://web-push.thelazyweb.dev/tutorial/) walks through every file.

## Run it

Build the library first (`pnpm install && pnpm run build` at the repository root), then:

```bash
pnpm install
pnpm run keys > .env     # Workers: > .dev.vars
pnpm run start:node      # or start:bun, start:deno; on http://localhost:3000
pnpm run dev:worker      # Workers, on http://localhost:8787
```

Put your own contact address in `VAPID_SUBJECT`. To deploy the Worker, create the KV namespace with `wrangler kv namespace create SUBSCRIPTIONS`, paste its id into `wrangler.toml`, store each value with `wrangler secret put`, then `pnpm run deploy`.

## Send a push

```bash
curl -X POST http://localhost:3000/api/push/broadcast \
  -H "Authorization: Bearer <your ADMIN_TOKEN>" \
  -d '{ "title": "Hello", "body": "Your first push", "url": "/" }'
```
