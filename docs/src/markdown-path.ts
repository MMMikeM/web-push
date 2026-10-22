/** Where a page's Markdown copy lives, relative to the site root: `index.md` for the home page. */
export const markdownPath = (pathname: string) =>
	pathname === "" ? "index.md" : `${pathname.replace(/\/$/, "")}.md`;
