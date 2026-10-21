// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";
import starlightLlmsTxt from "starlight-llms-txt";
import { markdownPages } from "./src/integrations/markdown-pages.ts";

export default defineConfig({
	site: "https://mmmikem.github.io",
	base: "/web-push",
	// The tutorial imports examples/app's files, which sit outside this project.
	vite: { server: { fs: { allow: [".."] } } },
	integrations: [
		starlight({
			title: "@mmmike/web-push",
			description:
				"Zero-dependency Web Push (RFC 8291) for Workers, Deno, Bun, Node, and browsers.",
			customCss: ["./src/styles/reference.css"],
			// The header's runtime menu sits beside the theme switcher.
			components: {
				ThemeSelect: "./src/components/ThemeSelect.astro",
				PageTitle: "./src/components/PageTitle.astro",
			},
			social: [{ icon: "github", label: "GitHub", href: "https://github.com/MMMikeM/web-push" }],
			plugins: [
				starlightLlmsTxt({
					// Whitespace minifying flattens tables and headings into run-on lines.
					minify: { whitespace: false },
					customSelectors: { all: [".sl-anchor-link"] },
				}),
			],
			sidebar: [
				{
					label: "Start here",
					items: [
						{ label: "Quickstart", slug: "getting-started" },
						{ label: "Build a complete app", slug: "tutorial" },
					],
				},
				{ label: "Recipes", items: [{ autogenerate: { directory: "guides" } }] },
				{ label: "Reference", items: [{ autogenerate: { directory: "reference" } }] },
			],
		}),
		markdownPages(),
	],
});
