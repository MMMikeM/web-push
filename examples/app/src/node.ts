import { readFile } from "node:fs/promises";
import {
	createServer,
	type IncomingMessage,
	type ServerResponse,
} from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { createApp } from "./app.ts";
import { memoryStore } from "./memory-store.ts";

const requireEnv = (name: string): string => {
	const value = process.env[name];
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

const PUBLIC_DIR = join(import.meta.dirname, "../public");
const CONTENT_TYPES: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
};

const serveStatic = async (
	pathname: string,
	response: ServerResponse,
): Promise<void> => {
	const file = normalize(
		join(PUBLIC_DIR, pathname === "/" ? "index.html" : pathname),
	);
	if (!file.startsWith(PUBLIC_DIR + sep)) {
		response.writeHead(404).end();
		return;
	}
	try {
		const body = await readFile(file);
		response.writeHead(200, {
			"content-type": CONTENT_TYPES[extname(file)] ?? "text/plain",
		});
		response.end(body);
	} catch {
		response.writeHead(404).end();
	}
};

const toRequest = async (incoming: IncomingMessage): Promise<Request> => {
	const headers = new Headers();
	for (const [name, value] of Object.entries(incoming.headers)) {
		if (value !== undefined) {
			headers.set(name, Array.isArray(value) ? value.join(", ") : value);
		}
	}
	const chunks: Buffer[] = [];
	for await (const chunk of incoming) {
		chunks.push(chunk as Buffer);
	}
	return new Request(
		new URL(incoming.url ?? "/", `http://${incoming.headers.host}`),
		{
			method: incoming.method,
			headers,
			body: chunks.length ? Buffer.concat(chunks) : undefined,
		},
	);
};

const server = createServer(async (incoming, response) => {
	const request = await toRequest(incoming);
	const { pathname } = new URL(request.url);
	if (!pathname.startsWith("/api/")) {
		await serveStatic(pathname, response);
		return;
	}
	const result = await app(request);
	response.writeHead(result.status, Object.fromEntries(result.headers));
	response.end(Buffer.from(await result.arrayBuffer()));
});

const port = Number(process.env.PORT ?? 3000);
server.listen(port, () => console.log(`http://localhost:${port}`));
