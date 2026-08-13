// Fail when the README "Small." bullet no longer matches what a consumer
// actually ships. Bundling before gzip is the point: dist files import each
// other (send.mjs is a shim over a shared chunk, client.mjs pulls the base64
// codec from vapid.mjs), so gzipping one dist file alone under-reports its entry.
//
// Runs directly under Node's type stripping (unflagged since 22.18 / 23.6), so
// this file sticks to erasable syntax — tsconfig.tools.json enforces that.
import { existsSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

const ENTRIES = [
	{ entry: "client", label: "browser client", claim: /([\d.]+) kB for the browser client/ },
	{ entry: "send", label: "server", claim: /([\d.]+) kB for the server/ },
	{ entry: "index", label: "whole package", claim: /whole package, ~([\d.]+) kB/ },
];

if (!existsSync("dist/index.mjs")) {
	console.error("dist/ is missing. Run `pnpm run build` first.");
	process.exit(2);
}

const bundledGzipSize = async (entry: string): Promise<number> => {
	const { outputFiles } = await build({
		entryPoints: [`dist/${entry}.mjs`],
		bundle: true,
		minify: true,
		format: "esm",
		write: false,
		// Every run warns that the shim's bare `import "./vapid.mjs"` is dropped
		// under sideEffects:false; expected, and errors still reject the promise.
		logLevel: "silent",
	});
	return gzipSync(outputFiles[0].contents, { level: 9 }).length;
};

// Environments gzip the same bytes a few dozen bytes apart (zlib builds
// differ), which flips exact 0.1 kB rounding at a boundary — CI measured the
// server entry at 2855 B where a laptop got 2828 B. Real growth still trips
// this: a small feature adds ~150 B minified+gzipped.
const TOLERANCE_KB = 0.1;

const readme = readFileSync("README.md", "utf8");

const results = await Promise.all(
	ENTRIES.map(async ({ entry, label, claim }) => {
		const bytes = await bundledGzipSize(entry);
		return {
			label,
			bytes,
			measured: (bytes / 1000).toFixed(1),
			documented: readme.match(claim)?.[1] ?? null,
		};
	}),
);

let stale = false;
for (const { label, bytes, measured, documented } of results) {
	const ok = documented !== null && Math.abs(bytes / 1000 - Number(documented)) <= TOLERANCE_KB;
	if (!ok) {
		stale = true;
	}
	console.log(
		`${ok ? "ok   " : "STALE"} ${label}: ${bytes} B → ${measured} kB (README says ${documented ?? "nothing"})`,
	);
}

if (stale) {
	console.error('README size figures are stale — update the "Small." bullet.');
	process.exit(1);
}
