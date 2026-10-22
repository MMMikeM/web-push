import pkg from "../../package.json";

const repositoryUrl = pkg.repository.url.replace(/^git\+/, "").replace(/\.git$/, "");

/** The library's identity, read from its package.json so the site never restates it. */
export const project = {
	name: pkg.name,
	description: pkg.description,
	keywords: pkg.keywords,
	license: pkg.license,
	licenseUrl: `https://spdx.org/licenses/${pkg.license}.html`,
	licenseFileUrl: `${repositoryUrl}/blob/main/LICENSE`,
	author: pkg.author,
	repositoryUrl,
	changelogUrl: `${repositoryUrl}/blob/main/CHANGELOG.md`,
	npmUrl: `https://www.npmjs.com/package/${pkg.name}`,
};
