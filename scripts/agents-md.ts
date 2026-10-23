// Builds dist/AGENTS.md during `vp pack`: the entry points and what each one
// exports, read from the build itself, then the rules from the docs site's
// "Rules for AI coding agents" page. It ships in the package, where an agent
// browsing node_modules finds it, and the markers let a project paste it into
// its own AGENTS.md and replace it on upgrade.
//
// Loaded by vite.config.ts, which is typechecked without Node types, so files
// are read through Rolldown's `this.fs`.
import type { Plugin } from "vite-plus";

const SITE = "https://web-push.thelazyweb.dev";
const RULES_PAGE = "docs/src/content/docs/ai-agents.md";

type PackageJson = {
	name: string;
	version: string;
	description: string;
	exports: Record<string, { default: string }>;
};

/** A root-absolute docs link becomes the URL of that page's Markdown copy. */
const toMarkdownLinks = (markdown: string): string =>
	markdown.replaceAll(
		/\]\((\/[^)\s#]*)(#[^)\s]*)?\)/g,
		(_, path: string, hash: string | undefined) =>
			`](${SITE}/${path === "/" ? "index" : path.slice(1).replace(/\/$/, "")}.md${hash ?? ""})`,
	);

/** The page from its first `##` heading on; the intro above it addresses readers of the site. */
const rulesFrom = (page: string): string => {
	const firstSection = page.indexOf("\n## ");
	if (firstSection === -1) {
		throw new Error(`${RULES_PAGE} has no ## section to ship`);
	}
	return toMarkdownLinks(page.slice(firstSection + 1).trim());
};

const referenceFor = (entry: string): string =>
	entry === "." ? `${SITE}/reference.md` : `${SITE}/reference/${entry.slice(2)}.md`;

const entryPointTable = (pkg: PackageJson, exportsByFile: Map<string, string[]>): string => {
	const rows = Object.entries(pkg.exports).map(([entry, { default: file }]) => {
		const names = exportsByFile.get(file.replace(/^\.\/dist\//, ""));
		if (!names) {
			throw new Error(`package.json exports ${entry} as ${file}, which the build didn't emit`);
		}
		const specifier = entry === "." ? pkg.name : `${pkg.name}/${entry.slice(2)}`;
		const list = names.map((name) => `\`${name}\``).join(", ");
		return `| \`${specifier}\` | ${list} | [reference](${referenceFor(entry)}) |`;
	});
	return ["| Import | Exports | Docs |", "| --- | --- | --- |", ...rows].join("\n");
};

/** Emits `AGENTS.md` next to the built entry points. */
export const agentsMd = (): Plugin => ({
	name: "web-push:agents-md",
	async generateBundle(_options, bundle) {
		const pkg = JSON.parse(
			await this.fs.readFile("package.json", { encoding: "utf8" }),
		) as PackageJson;
		const exportsByFile = new Map(
			Object.values(bundle).flatMap((output) =>
				output.type === "chunk" && output.isEntry && output.fileName.endsWith(".mjs")
					? [[output.fileName, output.exports.toSorted()] as const]
					: [],
			),
		);
		const marker = pkg.name;
		const source = [
			`<!-- ${marker} START -->`,
			`# ${pkg.name} ${pkg.version}`,
			pkg.description,
			"## Entry points",
			entryPointTable(pkg, exportsByFile),
			rulesFrom(await this.fs.readFile(RULES_PAGE, { encoding: "utf8" })),
			`<!-- ${marker} END -->`,
		].join("\n\n");
		this.emitFile({ type: "asset", fileName: "AGENTS.md", source: `${source}\n` });
	},
});
