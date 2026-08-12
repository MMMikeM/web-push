// Extract one version's section from CHANGELOG.md, for use as GitHub Release notes.
//
// Runs directly under Node's type stripping (unflagged since 22.18 / 23.6), so
// this file sticks to erasable syntax — tsconfig.tools.json enforces that.
import { readFileSync } from "node:fs";

const version = process.argv[2];
const path = process.argv[3] ?? "CHANGELOG.md";

if (!version) {
	console.error("usage: extract-changelog.ts <version> [changelogPath]");
	process.exit(2);
}

const versionSection = (lines: string[], target: string): string | null => {
	const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const heading = new RegExp(`^##\\s+\\[${escaped}\\]`);
	const anyVersion = /^##\s+\[/;

	const start = lines.findIndex((line) => heading.test(line));
	if (start === -1) {
		return null;
	}

	let end = lines.length;
	for (let i = start + 1; i < lines.length; i++) {
		if (anyVersion.test(lines[i])) {
			end = i;
			break;
		}
	}

	return lines
		.slice(start + 1, end)
		.join("\n")
		.trim();
};

const body = versionSection(readFileSync(path, "utf8").split("\n"), version);
if (body === null) {
	console.error(`No section for version ${version} in ${path}`);
	process.exit(1);
}
if (!body) {
	console.error(`Section for version ${version} is empty`);
	process.exit(1);
}

process.stdout.write(`${body}\n`);
