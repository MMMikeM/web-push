import { markdownPath } from "../src/markdown-path.ts";

type DataPoint = { indexes: string[]; blobs: string[]; doubles: number[] };

type Env = {
	ASSETS: { fetch: (request: Request) => Promise<Response> };
	// Optional, so `wrangler dev` without the binding still serves.
	VIEWS?: { writeDataPoint: (point: DataPoint) => void };
};

/** What answered a request: a page as HTML, a page negotiated to Markdown, or a `.md`/`.txt` file. */
type Served = "html" | "markdown" | "file";

/** The `q` an `Accept` header gives a media type: 1 when listed bare, 0 when absent. */
const quality = (accept: string, mediaType: string): number => {
	for (const range of accept.split(",")) {
		const [name = "", ...params] = range.split(";").map((part) => part.trim());
		if (name.toLowerCase() === mediaType) {
			const q = params.find((param) => param.startsWith("q="));
			return q ? Number(q.slice(2)) : 1;
		}
	}
	return 0;
};

const prefersMarkdown = (accept: string | null): boolean => {
	if (!accept) {
		return false;
	}
	const markdown = quality(accept, "text/markdown");
	return markdown > 0 && markdown >= quality(accept, "text/html");
};

const withHeaders = (response: Response, headers: Record<string, string>): Response => {
	const copy = new Response(response.body, response);
	for (const [name, value] of Object.entries(headers)) {
		copy.headers.set(name, value);
	}
	return copy;
};

// Server-side, so pages ship no analytics script. Bots stay in: which agents
// read the Markdown is the question, so queries filter by user agent instead.
// writeDataPoint doesn't block the response; never await it.
const logView = (env: Env, request: Request, response: Response, served: Served): void => {
	if (!env.VIEWS || request.method !== "GET") {
		return;
	}
	const { cf } = request as Request & { cf?: { country?: string } };
	env.VIEWS.writeDataPoint({
		indexes: [served],
		blobs: [
			new URL(request.url).pathname,
			served,
			request.headers.get("user-agent") ?? "",
			request.headers.get("accept") ?? "",
			request.headers.get("referer") ?? "",
			cf?.country ?? "",
		],
		doubles: [response.status],
	});
};

const isAgentFile = (pathname: string) => pathname.endsWith(".md") || pathname.endsWith(".txt");

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		// Every page URL ends in a slash; anything else is an asset or a redirect to a page.
		if (!url.pathname.endsWith("/")) {
			const response = await env.ASSETS.fetch(request);
			if (isAgentFile(url.pathname)) {
				logView(env, request, response, "file");
			}
			return response;
		}
		const markdownUrl = new URL(`/${markdownPath(url.pathname.slice(1))}`, url);

		if (prefersMarkdown(request.headers.get("accept"))) {
			const markdown = await env.ASSETS.fetch(new Request(markdownUrl, request));
			if (markdown.ok) {
				logView(env, request, markdown, "markdown");
				return withHeaders(markdown, {
					"Content-Type": "text/markdown; charset=utf-8",
					Vary: "Accept",
				});
			}
		}

		const page = await env.ASSETS.fetch(request);
		logView(env, request, page, "html");
		if (!page.ok || !page.headers.get("content-type")?.startsWith("text/html")) {
			return page;
		}
		return withHeaders(page, {
			Link: `<${markdownUrl.pathname}>; rel="alternate"; type="text/markdown"`,
			Vary: "Accept",
		});
	},
};
