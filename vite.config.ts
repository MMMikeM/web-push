import { defineConfig, type ViteUserConfig } from "vite-plus";
import { agentsMd } from "./scripts/agents-md";

// Typed, not inferred, so isolatedDeclarations accepts the default export.
const config: ViteUserConfig = defineConfig({
	fmt: {
		useTabs: true,
		printWidth: 100,
		ignorePatterns: [
			"dist",
			"docs/.astro",
			"docs/node_modules",
			// Generated from src/ on every docs build.
			"docs/src/content/docs/reference",
		],
		overrides: [
			{
				// Shown in the docs, whose content column fits about 80 characters.
				files: ["docs/**/*.md", "docs/**/*.mdx", "examples/**"],
				options: { printWidth: 80 },
			},
		],
	},
	lint: {
		plugins: ["typescript", "unicorn", "oxc", "node", "promise", "vitest", "import", "eslint"],
		categories: {
			correctness: "error",
			perf: "error",
			suspicious: "error",
		},
		rules: {
			eqeqeq: "error",
			"no-var": "error",
			"typescript/no-explicit-any": "error",
			"typescript/no-non-null-assertion": "error",
		},
		env: { builtin: true },
	},
	test: {
		environment: "node",
		include: ["test/**/*.test.ts"],
		// No `reporters` on purpose: with it unset, vitest auto-adds the
		// github-actions reporter in CI, which annotates failures in PR diffs.
		// Setting a custom list here would silently drop those annotations.
		coverage: {
			provider: "v8",
			include: ["src/**"],
			reporter: ["text", "html"],
			thresholds: { 100: true },
		},
	},
	pack: {
		entry: ["./src/index.ts", "./src/vapid.ts", "./src/send.ts", "./src/client.ts"],
		format: ["esm"],
		dts: true,
		clean: true,
		unbundle: true,
		// attw, publint and the bundler only warn by default; these make each
		// one fail the build instead.
		failOnWarn: true,
		attw: {
			profile: "esm-only",
			level: "error",
		},
		publint: { strict: true },
		plugins: [agentsMd()],
	},
});

export default config;
