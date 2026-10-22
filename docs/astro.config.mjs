// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";
import starlightLlmsTxt from "starlight-llms-txt";
import { markdownPages } from "./src/integrations/markdown-pages.ts";
import { project } from "./src/project.ts";

const site = "https://web-push.thelazyweb.dev";

const socialImage = {
	url: `${site}/og.png`,
	// The card's own text; re-render public/og.png when the home tagline changes.
	alt: "@mmmike/web-push: The whole Web Push flow, from subscribing in the browser to sending from the server, in one zero-dependency package.",
};

export default defineConfig({
	site,
	// The tutorial imports examples/app's files, which sit outside this project.
	vite: { server: { fs: { allow: [".."] } } },
	integrations: [
		starlight({
			title: "@mmmike/web-push",
			description:
				"Zero-dependency Web Push (RFC 8291) for Workers, Deno, Bun, Node, and browsers.",
			customCss: ["./src/styles/reference.css"],
			head: [
				{ tag: "meta", attrs: { property: "og:image", content: socialImage.url } },
				{ tag: "meta", attrs: { property: "og:image:width", content: "1200" } },
				{ tag: "meta", attrs: { property: "og:image:height", content: "630" } },
				{ tag: "meta", attrs: { property: "og:image:alt", content: socialImage.alt } },
				{ tag: "meta", attrs: { name: "twitter:image", content: socialImage.url } },
				{ tag: "meta", attrs: { name: "twitter:image:alt", content: socialImage.alt } },
				// The sizes keep Chrome on the SVG: https://evilmartians.com/chronicles/how-to-favicon-in-2021-six-files-that-fit-most-needs
				{ tag: "link", attrs: { rel: "icon", href: "/favicon.ico", sizes: "32x32" } },
				{ tag: "link", attrs: { rel: "apple-touch-icon", href: "/apple-touch-icon.png" } },
			],
			lastUpdated: true,
			editLink: { baseUrl: `${project.repositoryUrl}/edit/main/docs/` },
			routeMiddleware: "./src/routeData.ts",
			// The header's runtime menu sits beside the theme switcher.
			components: {
				ThemeSelect: "./src/components/ThemeSelect.astro",
				PageTitle: "./src/components/PageTitle.astro",
				MarkdownContent: "./src/components/MarkdownContent.astro",
				Footer: "./src/components/Footer.astro",
			},
			social: [{ icon: "github", label: "GitHub", href: "https://github.com/MMMikeM/web-push" }],
			plugins: [
				starlightLlmsTxt({
					details: [
						"`@mmmike/web-push` covers the whole Web Push flow in one zero-dependency package: VAPID keys (RFC 8292), payload encryption (RFC 8291, `aes128gcm`), sending from the server, and subscribing in the browser. It needs only `fetch` and `crypto.subtle`, so it runs on Cloudflare Workers, Deno, Bun, Vercel Edge, Node 22.12+, and browsers.",
						"Install with `npm install @mmmike/web-push`. Import the server side from `@mmmike/web-push/send`, the browser side from `@mmmike/web-push/client`, and key generation from `@mmmike/web-push/vapid`.",
						"Every page is also served as Markdown, at its URL with `.md` in place of the trailing slash (the home page at `index.md`). The key pages:",
						[
							["getting-started", "Quickstart: keys, service worker, subscribe, send"],
							["tutorial", "Build a complete app on Node, Bun, Deno, or Cloudflare Workers"],
							["compare", "How it compares to web-push and the edge-native alternatives"],
							["guides/runtime-setup", "Install and load VAPID keys on each runtime"],
							["guides/migrate-from-web-push", "Migrate from the web-push package"],
							["guides/send-to-many", "Fan one notification out to every subscriber"],
							["guides/handle-errors", "Retryable and permanent failures, Retry-After"],
							["guides/collapse-notifications", "Replace and expire with tag, topic, and ttl"],
							["guides/rotate-vapid-keys", "Rotate VAPID keys without losing subscribers"],
							["guides/secure-endpoints", "Keep subscription endpoints secret"],
							["guides/authenticated-uploads", "Send the subscription to a server that needs auth"],
							["guides/extension-service-workers", "Subscribe from an extension's service worker"],
							["reference", "API overview: every export and its entry point"],
							["reference/send", "API: sending"],
							["reference/client", "API: browser helpers"],
							["reference/vapid", "API: VAPID keys and base64url"],
						]
							.map(([page, summary]) => `- [${page}.md](${site}/${page}.md): ${summary}`)
							.join("\n"),
					].join("\n\n"),
					// llms-small.txt leaves the API reference and the tutorial to their .md pages.
					exclude: ["reference", "reference/**", "tutorial"],
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
						{ label: "How it compares", slug: "compare" },
					],
				},
				{ label: "Recipes", items: [{ autogenerate: { directory: "guides" } }] },
				{ label: "Reference", items: [{ autogenerate: { directory: "reference" } }] },
			],
		}),
		markdownPages(),
	],
});
