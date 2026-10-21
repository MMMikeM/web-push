import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { AstroIntegration } from "astro";
import type { Element, ElementContent, Root } from "hast";
import { matches, select, selectAll } from "hast-util-select";
import rehypeParse from "rehype-parse";
import rehypeRemark from "rehype-remark";
import remarkGfm from "remark-gfm";
import remarkStringify from "remark-stringify";
import { unified } from "unified";
import { remove } from "unist-util-remove";

const NOISE = [
	".sl-anchor-link",
	".sr-only",
	"script",
	"style",
	"runtime-select",
	"starlight-tabs-restore",
];

const textOf = (node: ElementContent): string =>
	node.type === "text"
		? node.value
		: node.type === "element"
			? node.children.map(textOf).join("")
			: "";

// Expressive Code renders each line as a block, which converts to doubled blank
// lines, and puts the language on <pre> where hast-util-to-mdast doesn't look.
// A file title in the frame header becomes a line above the block.
const prepareCodeBlocks = (tree: Root) => {
	for (const frame of selectAll(".expressive-code", tree)) {
		const pre = select("pre", frame);
		const code = select("code", frame);
		const language = pre?.properties.dataLanguage;
		if (code) {
			// An empty line holds a lone "\n" to keep its height.
			const lines = selectAll(".ec-line", code).map((line) => textOf(line).replace(/\n$/, ""));
			code.children = [{ type: "text", value: lines.join("\n") }];
			code.properties.className = typeof language === "string" ? [`language-${language}`] : [];
		}
		const title = select("figcaption .title", frame);
		const titleText = title?.children.find((child) => child.type === "text")?.value.trim();
		frame.tagName = "div";
		frame.children = [...(titleText ? [paragraph(`\`${titleText}\``)] : []), ...(pre ? [pre] : [])];
	}
};

// Tabs become a list: each runtime's label, then its panel.
const prepareTabs = (tree: Root) => {
	for (const tabs of selectAll("starlight-tabs", tree)) {
		const labels = selectAll('[role="tab"]', tabs).map((tab) =>
			tab.children
				.filter((child) => child.type === "text")
				.map((child) => child.value.trim())
				.join(""),
		);
		const panels = selectAll('[role="tabpanel"]', tabs);
		tabs.tagName = "ul";
		tabs.properties = {};
		tabs.children = panels.map((panel, index): Element => ({
			type: "element",
			tagName: "li",
			properties: {},
			children: [paragraph(`**${labels[index] ?? ""}**`), panel],
		}));
	}
};

const paragraph = (markdown: string): Element => ({
	type: "element",
	tagName: "p",
	properties: {},
	children: [{ type: "text", value: markdown }],
});

const toMarkdown = async (html: string): Promise<string | undefined> => {
	const page = unified().use(rehypeParse).parse(html);
	const title = select("h1#_top", page);
	const content = select(".sl-markdown-content", page);
	if (!title || !content) {
		return undefined;
	}
	const tree: Root = { type: "root", children: [title, ...(content.children as ElementContent[])] };
	remove(
		tree,
		(node) => node.type === "comment" || NOISE.some((selector) => matches(selector, node)),
	);
	prepareCodeBlocks(tree);
	prepareTabs(tree);
	const processor = unified().use(rehypeRemark).use(remarkGfm).use(remarkStringify);
	const markdown = processor.stringify(await processor.run(tree));
	// The code titles and tab labels above were written as Markdown already.
	return markdown.replaceAll("\\`", "`").replaceAll("\\*\\*", "**");
};

/**
 * Writes `<page>.md` beside each built page, converted from the rendered HTML, so
 * MDX components arrive as their output: code from `?raw` imports, every tab's panel.
 */
export const markdownPages = (): AstroIntegration => ({
	name: "markdown-pages",
	hooks: {
		"astro:build:done": async ({ dir, pages }) => {
			const outDir = fileURLToPath(dir);
			await Promise.all(
				pages
					.filter(({ pathname }) => pathname !== "" && pathname !== "404/")
					.map(async ({ pathname }) => {
						const html = await readFile(`${outDir}${pathname}index.html`, "utf8");
						const markdown = await toMarkdown(html);
						if (markdown) {
							await writeFile(`${outDir}${pathname.replace(/\/$/, "")}.md`, markdown);
						}
					}),
			);
		},
	},
});
