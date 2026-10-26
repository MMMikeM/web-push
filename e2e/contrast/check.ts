import { AxeBuilder } from "@axe-core/playwright";
import { chromium, type Page } from "playwright";

// Checks text contrast on every docs page against WCAG AA, in both themes:
// `pnpm run contrast [base-url]`, against the deployed site by default. The
// pages come from the deployed sitemap, since `astro dev` doesn't serve one.

const SITE = "https://web-push.thelazyweb.dev";
const THEMES = ["dark", "light"] as const;
// Long enough for the hero's margin note to write itself in.
const SETTLE_MS = 2500;

type Theme = (typeof THEMES)[number];
type Failure = {
	theme: Theme;
	page: string;
	target: string;
	html: string;
	data: Record<string, unknown>;
};

const base = process.argv[2] ?? SITE;
const sitemap = await (await fetch(`${SITE}/sitemap-0.xml`)).text();
const paths = [...sitemap.matchAll(/<loc>https?:\/\/[^/]+([^<]*)<\/loc>/g)].map(([, path]) => path);

const fill = (page: Page, selector: string, text: string) =>
	page.locator(selector).evaluate((element, value) => {
		element.textContent = value;
	}, text);

const show = (page: Page, selector: string) =>
	page.locator(selector).evaluate((element: HTMLElement) => {
		element.hidden = false;
	});

/** The push demo's toast and countdown, which are hidden until someone sends. */
const showDemoStates = async (page: Page) => {
	await fill(page, "push-demo .toast .title", "Hello from @mmmike/web-push");
	await fill(page, "push-demo .toast .body", "Sent by this site's Cloudflare Worker.");
	await fill(page, "push-demo .countdown .seconds", "4");
	await show(page, "push-demo .toast");
	await show(page, "push-demo .countdown");
};

const pages: { path: string; label: string; prepare?: (page: Page) => Promise<void> }[] = [
	...paths.map((path) => ({ path, label: path })),
	{ path: "/", label: "/ with the demo's toast and countdown", prepare: showDemoStates },
];

const browser = await chromium.launch();
const failures: Failure[] = [];
let undecided = 0;

for (const theme of THEMES) {
	for (const { path, label, prepare } of pages) {
		const context = await browser.newContext({
			viewport: { width: 1280, height: 900 },
			colorScheme: theme,
		});
		await context.addInitScript((value) => localStorage.setItem("starlight-theme", value), theme);
		const page = await context.newPage();
		await page.goto(new URL(path, base).href, { waitUntil: "networkidle" });
		await prepare?.(page);
		await page.waitForTimeout(SETTLE_MS);
		const results = await new AxeBuilder({ page }).withRules(["color-contrast"]).analyze();
		for (const node of results.violations.flatMap((violation) => violation.nodes)) {
			failures.push({
				theme,
				page: label,
				target: node.target.join(" "),
				html: node.html.slice(0, 120),
				data: (node.any[0]?.data ?? {}) as Record<string, unknown>,
			});
		}
		undecided += results.incomplete.reduce((total, item) => total + item.nodes.length, 0);
		await context.close();
	}
}
await browser.close();

console.log(
	`${pages.length} pages in ${THEMES.join(" and ")}: ${failures.length} below WCAG AA contrast.`,
);
for (const { theme, page, target, html, data } of failures) {
	console.log(
		`- [${theme}] ${page} ${target}: ${data.contrastRatio}:1, needs ${data.expectedContrastRatio}, ${data.fgColor} on ${data.bgColor}\n  ${html}`,
	);
}
// Text over a gradient or another element, and lone glyphs: axe leaves these
// for a person to check.
console.log(`${undecided} elements axe couldn't decide on.`);
process.exitCode = failures.length > 0 ? 1 : 0;
