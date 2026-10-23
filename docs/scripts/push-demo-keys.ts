import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVapidKeys } from "../../src/vapid.ts";

// Gives the deployed docs Worker its own VAPID pair for the home page's push
// demo. Run once, logged in to wrangler: `node docs/scripts/push-demo-keys.ts`.
// The private key goes to `wrangler secret put` on stdin and is never printed.
// Running it again replaces the pair, which only orphans demo subscriptions.

const docsDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const { publicKey, privateKey } = await generateVapidKeys();

for (const [name, value] of [
	["DEMO_VAPID_PUBLIC_KEY", publicKey],
	["DEMO_VAPID_PRIVATE_KEY", privateKey],
] as const) {
	const { status } = spawnSync("pnpm", ["exec", "wrangler", "secret", "put", name], {
		cwd: docsDir,
		input: value,
		stdio: ["pipe", "inherit", "inherit"],
	});
	if (status !== 0) {
		throw new Error(`wrangler secret put ${name} failed`);
	}
}
console.log(`Demo VAPID public key: ${publicKey}`);
