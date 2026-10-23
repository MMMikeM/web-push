import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const contentDir = fileURLToPath(new URL("content/docs/", import.meta.url));

let inGitCheckout: boolean | undefined;

/** A source tarball has no git checkout; the build then warns once and skips lastmod. */
const isGitCheckout = (): boolean => {
	if (inGitCheckout === undefined) {
		try {
			execFileSync("git", ["rev-parse", "--is-inside-work-tree"], { stdio: "ignore" });
			inGitCheckout = true;
		} catch {
			inGitCheckout = false;
			console.warn("last-modified: no git checkout, so the sitemap goes without lastmod");
		}
	}
	return inGitCheckout;
};

/**
 * When git last changed a page's source file, the same commit Starlight's "Last updated" shows.
 * Undefined for a page with no tracked source, such as the generated API reference, or
 * when the build has no git checkout to read.
 */
export const lastModified = (pathname: string): string | undefined => {
	const slug = pathname.replace(/^\/|\/$/g, "") || "index";
	const source = [".md", ".mdx"].map((ext) => `${contentDir}${slug}${ext}`).find(existsSync);
	if (!source || !isGitCheckout()) {
		return undefined;
	}
	const committedAt = execFileSync("git", ["log", "-1", "--format=%cI", "--", source], {
		encoding: "utf8",
	}).trim();
	return committedAt || undefined;
};
