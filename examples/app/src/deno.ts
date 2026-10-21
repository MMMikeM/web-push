import { extname } from "node:path";
import { createApp } from "./app.ts";
import { memoryStore } from "./memory-store.ts";

const requireEnv = (name: string): string => {
	const value = Deno.env.get(name);
	if (!value) {
		throw new Error(
			`Missing ${name}: copy .env.example to .env and fill it in`,
		);
	}
	return value;
};

const app = createApp({
	vapid: {
		publicKey: requireEnv("VAPID_PUBLIC_KEY"),
		privateKey: requireEnv("VAPID_PRIVATE_KEY"),
		subject: requireEnv("VAPID_SUBJECT"),
	},
	adminToken: requireEnv("ADMIN_TOKEN"),
	store: memoryStore(),
});

const PUBLIC_DIR = new URL("../public/", import.meta.url);
const CONTENT_TYPES: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
};

const serveStatic = async (pathname: string): Promise<Response> => {
	const url = new URL(
		pathname === "/" ? "index.html" : `.${pathname}`,
		PUBLIC_DIR,
	);
	if (!url.href.startsWith(PUBLIC_DIR.href)) {
		return new Response("Not found", { status: 404 });
	}
	try {
		const body = await Deno.readFile(url);
		const contentType = CONTENT_TYPES[extname(url.pathname)] ?? "text/plain";
		return new Response(body, { headers: { "content-type": contentType } });
	} catch {
		return new Response("Not found", { status: 404 });
	}
};

Deno.serve({ port: Number(Deno.env.get("PORT") ?? 3000) }, (request) => {
	const { pathname } = new URL(request.url);
	return pathname.startsWith("/api/") ? app(request) : serveStatic(pathname);
});
