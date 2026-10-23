import { execFile } from "node:child_process";
import { appendFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

// Startup times vary by machine, so the docs quote no figure for them and only
// their claims are checked. Upload sizes are checked to the figure.

const WORKERS = ["empty", "web-push", "mmmike"] as const;
type Worker = (typeof WORKERS)[number];
const LABELS: Record<Worker, string> = {
	empty: "Empty Worker",
	"web-push": "`web-push`",
	mmmike: "`@mmmike/web-push`",
};

const STARTUP_RUNS = 7;
// The docs say web-push takes longer to start and this package starts as fast
// as an empty Worker. The profiler samples about every 1.5 ms.
const WEB_PUSH_MIN_EXTRA_MS = 5;
const MMMIKE_MAX_EXTRA_MS = 2;

const README = fileURLToPath(new URL("../../README.md", import.meta.url));
const COMPARE = fileURLToPath(new URL("../../docs/src/content/docs/compare.md", import.meta.url));

const SIZE_CLAIMS: { file: string; claim: RegExp; worker: Worker; digits: number }[] = [
	{
		file: README,
		claim: /sends with it uploads about ([\d.]+) kB gzipped/,
		worker: "web-push",
		digits: 0,
	},
	{
		file: README,
		claim: /using this package uploads about ([\d.]+) kB/,
		worker: "mmmike",
		digits: 0,
	},
	{ file: COMPARE, claim: /uploads ([\d.]+) kB gzipped with it/, worker: "web-push", digits: 0 },
	{
		file: COMPARE,
		claim: /With `@mmmike\/web-push` it uploads ([\d.]+) kB/,
		worker: "mmmike",
		digits: 1,
	},
];

const run = promisify(execFile);

const wrangler = async (worker: Worker, args: string[]): Promise<string> => {
	const { stdout } = await run("pnpm", ["exec", "wrangler", ...args], {
		cwd: fileURLToPath(new URL(`${worker}/`, import.meta.url)),
		env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
	});
	return stdout;
};

/** Wrangler reports KiB; the docs and the size badge use kB. */
const gzipKb = async (worker: Worker, outDir: string): Promise<number> => {
	const output = await wrangler(worker, ["deploy", "--dry-run", "--outdir", outDir]);
	const kib = /gzip: ([\d.]+) KiB/.exec(output)?.[1];
	if (!kib) {
		throw new Error(`wrangler printed no upload size for ${worker}:\n${output}`);
	}
	return (Number(kib) * 1024) / 1000;
};

const startupMs = async (worker: Worker, profile: string): Promise<number> => {
	await wrangler(worker, ["check", "startup", "--outfile", profile]);
	const { startTime, endTime } = JSON.parse(await readFile(profile, "utf8")) as {
		startTime: number;
		endTime: number;
	};
	return (endTime - startTime) / 1000;
};

const median = (values: number[]): number => {
	const sorted = values.toSorted((a, b) => a - b);
	return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
};

const scratch = await mkdtemp(join(tmpdir(), "worker-cost-"));
const sizes = new Map<Worker, number>();
const startups = new Map<Worker, number>();
try {
	for (const worker of WORKERS) {
		sizes.set(worker, await gzipKb(worker, join(scratch, worker)));
		const runs: number[] = [];
		for (let i = 0; i < STARTUP_RUNS; i++) {
			runs.push(await startupMs(worker, join(scratch, `${worker}-${i}.cpuprofile`)));
		}
		startups.set(worker, median(runs));
	}
} finally {
	await rm(scratch, { recursive: true, force: true });
}

const extraMs = (worker: Worker): number =>
	(startups.get(worker) ?? Number.NaN) - (startups.get("empty") ?? Number.NaN);

// `|| 0` turns a noise-sized -0 into 0.
const ms = (value: number): string => (Math.round(value * 10) / 10 || 0).toFixed(1);

const table = [
	"| Worker | Upload, gzipped | Startup, median | Over an empty Worker |",
	"| --- | --- | --- | --- |",
	...WORKERS.map(
		(worker) =>
			`| ${LABELS[worker]} | ${sizes.get(worker)?.toFixed(2)} kB | ${startups.get(worker)?.toFixed(1)} ms | ${worker === "empty" ? "" : `${ms(extraMs(worker))} ms`} |`,
	),
].join("\n");
console.log(table);
if (process.env.GITHUB_STEP_SUMMARY) {
	await appendFile(process.env.GITHUB_STEP_SUMMARY, `${table}\n`);
}

const failures: string[] = [];
for (const { file, claim, worker, digits } of SIZE_CLAIMS) {
	const documented = claim.exec(await readFile(file, "utf8"))?.[1];
	const measured = sizes.get(worker)?.toFixed(digits);
	if (documented !== measured) {
		failures.push(
			`${file} says ${documented ?? "nothing"} kB for ${worker}, measured ${measured} kB (${claim})`,
		);
	}
}
if (!(extraMs("web-push") >= WEB_PUSH_MIN_EXTRA_MS)) {
	failures.push(`web-push started only ${ms(extraMs("web-push"))} ms slower than an empty Worker`);
}
if (!(extraMs("mmmike") <= MMMIKE_MAX_EXTRA_MS)) {
	failures.push(`@mmmike/web-push started ${ms(extraMs("mmmike"))} ms slower than an empty Worker`);
}
if (failures.length > 0) {
	console.error(`\nThe docs no longer match:\n${failures.join("\n")}`);
	process.exitCode = 1;
}
