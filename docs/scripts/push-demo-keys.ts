import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVapidKeys } from "../../src/vapid.ts";

// Gives the deployed docs Worker its own VAPID pair for the home page's push
// demo. Run once, logged in to wrangler: `node docs/scripts/push-demo-keys.ts`.
// Both keys go in one `wrangler secret bulk` call on stdin, so the Worker never
// runs with half a pair and the private key is never printed or written to disk.
// Running it again replaces the pair, which only orphans demo subscriptions.

const docsDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const { publicKey, privateKey } = await generateVapidKeys();

const { status } = spawnSync("pnpm", ["exec", "wrangler", "secret", "bulk"], {
	cwd: docsDir,
	input: JSON.stringify({
		DEMO_VAPID_PUBLIC_KEY: publicKey,
		DEMO_VAPID_PRIVATE_KEY: privateKey,
	}),
	stdio: ["pipe", "inherit", "inherit"],
});
if (status !== 0) {
	throw new Error("wrangler secret bulk failed; the Worker keeps its previous pair");
}
console.log(`Demo VAPID public key: ${publicKey}`);
