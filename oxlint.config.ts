import { defineConfig } from "oxlint";

export default defineConfig({
	plugins: ["typescript", "unicorn", "oxc"],
	categories: { correctness: "error" },
	rules: {
		"no-shadow": "error",
		eqeqeq: "error",
		"no-var": "error",
		"no-eval": "error",
		"typescript/no-explicit-any": "error",
		"typescript/no-non-null-assertion": "error",
		"unicorn/no-array-sort": "error",
		// Flags casts that stopped being necessary — this codebase carries a lot of
		// `as Uint8Array<ArrayBuffer>` to satisfy WebCrypto's BufferSource.
		"typescript/no-unnecessary-type-assertion": "error",
	},
	env: { builtin: true },
});
