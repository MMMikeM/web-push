// Loaded by vite.config.ts, which is typechecked without Node types, so files
// are read through Rolldown's `this.fs`.
import type { Plugin } from "vite-plus";
import { markdownUrl } from "../docs/src/markdown-path.ts";

const HOME = "https://web-push.thelazyweb.dev/";
const RULES_PAGE = "docs/src/content/docs/ai-agents.md";

type PackageJson = {
	name: string;
	version: string;
	description: string;
	exports: Record<string, { default: string }>;
};

/**
 * Root-absolute links get the site's host, since the file is read far from it.
 * A page's (ending in `/`) points at its Markdown copy instead.
 */
const toAbsoluteLinks = (markdown: string): string =>
	markdown.replaceAll(
		/\]\((\/[^)\s#]*)(#[^)\s]*)?(\s+"[^"]*")?\)/g,
		(_, path: string, hash = "", title = "") =>
			`](${path.endsWith("/") ? markdownUrl(path.slice(1), HOME) : new URL(path, HOME).href}${hash}${title})`,
	);

/** The page from its first `##` heading on; the intro above it addresses readers of the site. */
const rulesFrom = (page: string): string => {
	const firstSection = page.indexOf("\n## ");
	if (firstSection === -1) {
		throw new Error(`${RULES_PAGE} has no ## section to ship`);
	}
	return toAbsoluteLinks(page.slice(firstSection + 1).trim());
};

const referenceFor = (entry: string): string =>
	markdownUrl(entry === "." ? "reference/" : `reference/${entry.slice(2)}/`, HOME);

/** What each built file exports, and which names its declarations mark `@deprecated`. */
type BuiltExports = { byFile: Map<string, string[]>; deprecated: Set<string> };

/** Names whose JSDoc, directly above their declaration, says `@deprecated`. */
const deprecatedIn = (declarations: string): string[] =>
	[
		...declarations.matchAll(
			/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*export declare (?:const|function|class|type|interface) (\w+)/g,
		),
	].flatMap(([, doc, name]) => (doc?.includes("@deprecated") && name ? [name] : []));

const codeList = (names: string[], deprecated: Set<string>): string =>
	names
		.map((name) => (deprecated.has(name) ? `\`${name}\` (deprecated)` : `\`${name}\``))
		.join(", ");

const entryPointTable = (pkg: PackageJson, built: BuiltExports): string => {
	const rows = Object.entries(pkg.exports).map(([entry, { default: file }]) => {
		const base = file.replace(/^\.\/dist\//, "").replace(/\.mjs$/, "");
		const values = built.byFile.get(`${base}.mjs`);
		if (!values) {
			throw new Error(`package.json exports ${entry} as ${file}, which the build didn't emit`);
		}
		// The declaration file lists types as well as values; what isn't a value is a type.
		const types = (built.byFile.get(`${base}.d.mts`) ?? []).filter(
			(name) => !values.includes(name),
		);
		const specifier = entry === "." ? pkg.name : `${pkg.name}/${entry.slice(2)}`;
		return `| \`${specifier}\` | ${codeList(values, built.deprecated)} | ${codeList(types, built.deprecated)} | [reference](${referenceFor(entry)}) |`;
	});
	return [
		"| Import | Functions and classes | Types | Docs |",
		"| --- | --- | --- | --- |",
		...rows,
	].join("\n");
};

/** Emits `AGENTS.md` next to the built entry points. */
export const agentsMd = (): Plugin => ({
	name: "web-push:agents-md",
	async generateBundle(_options, bundle) {
		const pkg = JSON.parse(
			await this.fs.readFile("package.json", { encoding: "utf8" }),
		) as PackageJson;
		const entries = Object.values(bundle).flatMap((output) =>
			output.type === "chunk" && output.isEntry ? [output] : [],
		);
		const built: BuiltExports = {
			byFile: new Map(entries.map((chunk) => [chunk.fileName, chunk.exports.toSorted()])),
			deprecated: new Set(
				entries
					.filter((chunk) => chunk.fileName.endsWith(".d.mts"))
					.flatMap((chunk) => deprecatedIn(chunk.code)),
			),
		};
		const marker = pkg.name;
		const source = [
			`<!-- ${marker} START -->`,
			`# ${pkg.name} ${pkg.version}`,
			pkg.description,
			"## Entry points",
			entryPointTable(pkg, built),
			rulesFrom(await this.fs.readFile(RULES_PAGE, { encoding: "utf8" })),
			`<!-- ${marker} END -->`,
		].join("\n\n");
		this.emitFile({ type: "asset", fileName: "AGENTS.md", source: `${source}\n` });
	},
});
