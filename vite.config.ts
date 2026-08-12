import { defineConfig } from "vite-plus";

export default defineConfig({
	fmt: {
		useTabs: true,
		printWidth: 100,
		ignorePatterns: ["dist"],
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
		coverage: {
			provider: "v8",
			include: ["src/**"],
			reporter: ["text", "html"],
		},
	},
	pack: {
		entry: ["./src/index.ts", "./src/vapid.ts", "./src/send.ts", "./src/client.ts"],
		format: ["esm"],
		dts: true,
		clean: true,
		attw: {
			profile: "esm-only",
		},
		publint: true,
	},
});
