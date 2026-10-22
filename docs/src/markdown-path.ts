/** Where a page's Markdown copy lives, relative to the site root: `index.md` for the home page. */
export const markdownPath = (pathname: string) =>
	pathname === "" ? "index.md" : `${pathname.replace(/\/$/, "")}.md`;

/** The full URL of a page's Markdown copy, given the site's home page URL. */
export const markdownUrl = (id: string, home: string) => new URL(markdownPath(id), home).href;
