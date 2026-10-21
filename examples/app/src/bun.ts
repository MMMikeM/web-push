import { createApp } from "./app.ts";
import { memoryStore } from "./memory-store.ts";

const requireEnv = (name: string): string => {
	const value = Bun.env[name];
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

const serveStatic = async (pathname: string): Promise<Response> => {
	const url = new URL(
		pathname === "/" ? "index.html" : `.${pathname}`,
		PUBLIC_DIR,
	);
	const file = Bun.file(url);
	if (!url.href.startsWith(PUBLIC_DIR.href) || !(await file.exists())) {
		return new Response("Not found", { status: 404 });
	}
	return new Response(file);
};

const server = Bun.serve({
	port: Number(Bun.env.PORT ?? 3000),
	fetch: (request) => {
		const { pathname } = new URL(request.url);
		return pathname.startsWith("/api/") ? app(request) : serveStatic(pathname);
	},
});

console.log(`http://localhost:${server.port}`);
