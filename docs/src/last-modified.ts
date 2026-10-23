import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const contentDir = fileURLToPath(new URL("content/docs/", import.meta.url));

/**
 * When git last changed a page's source file, the same commit Starlight's "Last updated" shows.
 * Undefined for a page with no tracked source, such as the generated API reference, or
 * when the build has no git history to read.
 */
export const lastModified = (pathname: string): string | undefined => {
	const slug = pathname.replace(/^\/|\/$/g, "") || "index";
	const source = [".md", ".mdx"].map((ext) => `${contentDir}${slug}${ext}`).find(existsSync);
	if (!source) {
		return undefined;
	}
	try {
		const committedAt = execFileSync("git", ["log", "-1", "--format=%cI", "--", source], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
		return committedAt || undefined;
	} catch {
		// A build without git, such as one from a source tarball, gets no lastmod.
		return undefined;
	}
};
