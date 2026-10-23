import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { type CheckResult, report } from "./checks.ts";

const PORT = 8790;
const config = fileURLToPath(new URL("wrangler.jsonc", import.meta.url));

const wrangler = spawn(
	"pnpm",
	["exec", "wrangler", "dev", "--config", config, "--port", String(PORT), "--ip", "127.0.0.1"],
	{ stdio: ["ignore", "pipe", "inherit"] },
);
let output = "";
wrangler.stdout.on("data", (chunk: Buffer) => {
	output += chunk;
});

try {
	for (let waited = 0; !output.includes("Ready on"); waited += 250) {
		if (waited > 60_000 || wrangler.exitCode !== null) {
			throw new Error(`wrangler dev didn't start:\n${output}`);
		}
		await sleep(250);
	}
	const response = await fetch(`http://127.0.0.1:${PORT}/`);
	const { runtime, results } = (await response.json()) as {
		runtime: string;
		results: CheckResult[];
	};
	console.log(report(results, runtime));
	if (results.some(({ passed }) => !passed)) {
		process.exitCode = 1;
	}
} finally {
	wrangler.kill();
}
