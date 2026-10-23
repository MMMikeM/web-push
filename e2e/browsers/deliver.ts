import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { PushSubscriptionData } from "@mmmike/web-push";
import { rawPayload, sendPushNotification } from "@mmmike/web-push/send";
import { generateVapidKeys } from "@mmmike/web-push/vapid";
import { type BrowserContext, chromium, firefox } from "playwright";
import { type CheckResult, report } from "../conformance/checks.ts";

const DELIVERY_TIMEOUT_MS = 60_000;

const publicDir = fileURLToPath(new URL("public/", import.meta.url));
const distDir = fileURLToPath(new URL("../../dist/", import.meta.url));
const contentTypes: Record<string, string> = {
	".html": "text/html",
	".js": "text/javascript",
	".mjs": "text/javascript",
};

/** The test page, its service worker, and the built client it imports. */
const filePathFor = (pathname: string): string =>
	pathname === "/"
		? join(publicDir, "index.html")
		: pathname.startsWith("/dist/")
			? join(distDir, pathname.slice("/dist/".length))
			: join(publicDir, pathname);

// 127.0.0.1 is a secure context in every browser, so it can register a service worker.
const server = createServer(async (request, response) => {
	const path = filePathFor(new URL(request.url ?? "/", "http://localhost").pathname);
	try {
		const body = await readFile(path);
		response.writeHead(200, { "Content-Type": contentTypes[extname(path)] ?? "text/plain" });
		response.end(body);
	} catch {
		response.writeHead(404).end();
	}
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

type E2eWindow = {
	e2e: {
		received: string[];
		subscribe: (vapidPublicKey: string) => Promise<PushSubscriptionData>;
	};
};

// Push needs a persistent profile in both: a fresh context is private
// browsing, where the Push API is off.
const browsers: Record<string, (profileDir: string) => Promise<BrowserContext>> = {
	// Playwright's own Chromium has no credentials for Google's push service,
	// so this is the installed Chrome.
	Chrome: (profileDir) => chromium.launchPersistentContext(profileDir, { channel: "chrome" }),
	// Playwright's Firefox build ships with push switched off and no server set.
	Firefox: (profileDir) =>
		firefox.launchPersistentContext(profileDir, {
			firefoxUserPrefs: {
				"dom.push.enabled": true,
				"dom.push.connection.enabled": true,
				"dom.push.serverURL": "wss://push.services.mozilla.com/",
				"permissions.default.desktop-notification": 1,
			},
		}),
};

/** Subscribe in the browser, send from here through the real push service, and wait for it to arrive. */
const deliverTo = async (context: BrowserContext): Promise<void> => {
	await context.grantPermissions(["notifications"], { origin });
	const page = await context.newPage();
	await page.goto(origin);
	const vapid = { ...(await generateVapidKeys()), subject: "mailto:e2e@example.com" };
	const subscription = await page.evaluate(
		(key) => (globalThis as unknown as E2eWindow).e2e.subscribe(key),
		vapid.publicKey,
	);
	const message = `delivered ✓ ${crypto.randomUUID()}`;
	const accepted = await sendPushNotification(subscription, rawPayload(message), vapid, {
		ttl: 60,
		urgency: "high",
		topic: "e2e",
	});
	if (!accepted) {
		throw new Error(`${new URL(subscription.endpoint).host} reported the subscription gone`);
	}
	await page.waitForFunction(
		(expected) => (globalThis as unknown as E2eWindow).e2e.received.includes(expected),
		message,
		{ timeout: DELIVERY_TIMEOUT_MS },
	);
};

// `node browsers/deliver.ts chrome` runs one; no arguments runs them all.
const requested = process.argv.slice(2).map((name) => name.toLowerCase());
const selected = Object.entries(browsers).filter(
	([name]) => requested.length === 0 || requested.includes(name.toLowerCase()),
);

const results: CheckResult[] = [];
for (const [name, launch] of selected) {
	const profileDir = await mkdtemp(join(tmpdir(), `web-push-${name}-`));
	let context: BrowserContext | undefined;
	try {
		context = await launch(profileDir);
		await deliverTo(context);
		results.push({ name: `${name} receives and decrypts a push`, passed: true });
	} catch (error) {
		results.push({
			name: `${name} receives and decrypts a push`,
			passed: false,
			detail: String(error),
		});
	} finally {
		await context?.close();
		await rm(profileDir, { recursive: true, force: true });
	}
}
server.close();

console.log(report(results, `Node ${process.version}, through each browser's push service`));
if (results.some(({ passed }) => !passed)) {
	process.exitCode = 1;
}
