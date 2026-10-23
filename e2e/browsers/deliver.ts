import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { PushSubscriptionData } from "@mmmike/web-push";
import { rawPayload, sendPushNotification } from "@mmmike/web-push/send";
import { generateVapidKeys } from "@mmmike/web-push/vapid";
import { type BrowserContext, chromium, firefox } from "playwright";
import { type CheckResult, report } from "../conformance/checks.ts";

const DELIVERY_TIMEOUT_MS = 60_000;
// Chrome registers a fresh profile with Google first, which has taken over 30 s.
const SUBSCRIBE_TIMEOUT_MS = 90_000;

// Google's push service answers 410 for a few seconds after a subscription is
// made (see "Right after subscribing" in guides/handle-errors.md), and this
// sends to one made moments earlier. The result reports any resend.
const RESEND_GAPS_MS = [0, 2000, 4000, 8000, 16000, 32000];

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

/**
 * Subscribe in the browser, send from here through the real push service, and
 * wait for it to arrive. Returns a note when the push needed resending.
 */
const deliverTo = async (context: BrowserContext): Promise<string | undefined> => {
	await context.grantPermissions(["notifications"], { origin });
	const page = await context.newPage();
	await page.goto(origin);
	const vapid = { ...(await generateVapidKeys()), subject: "mailto:e2e@example.com" };
	// `evaluate` waits as long as the page's promise does, and a service worker
	// that never activates leaves `subscribe` pending forever.
	const subscription = await Promise.race([
		page.evaluate(
			(key) => (globalThis as unknown as E2eWindow).e2e.subscribe(key),
			vapid.publicKey,
		),
		sleep(SUBSCRIBE_TIMEOUT_MS, undefined, { ref: false }).then(() => {
			throw new Error(`subscribe didn't settle within ${SUBSCRIBE_TIMEOUT_MS} ms`);
		}),
	]);
	const message = `delivered ✓ ${crypto.randomUUID()}`;
	const statuses: number[] = [];
	const logger = {
		debug: (_: string, data?: { status?: number }) => statuses.push(Number(data?.status)),
	};
	let accepted = false;
	for (const gapMs of RESEND_GAPS_MS) {
		if (accepted) {
			break;
		}
		await sleep(gapMs);
		accepted = await sendPushNotification(subscription, rawPayload(message), vapid, {
			ttl: 60,
			urgency: "high",
			topic: "e2e",
			logger,
		});
	}
	const pushService = new URL(subscription.endpoint).host;
	if (!accepted) {
		throw new Error(`${pushService} answered every send with ${statuses.join(", ")}`);
	}
	try {
		await page.waitForFunction(
			(expected) => (globalThis as unknown as E2eWindow).e2e.received.includes(expected),
			message,
			{ timeout: DELIVERY_TIMEOUT_MS },
		);
	} catch (error) {
		const state = await page.evaluate(() => ({
			received: (globalThis as unknown as E2eWindow).e2e.received,
			worker: navigator.serviceWorker.controller?.state ?? "no controller",
		}));
		throw new Error(`${pushService} accepted the push, but the page got ${JSON.stringify(state)}`, {
			cause: error,
		});
	}
	return statuses.length > 1 ? `resent after ${statuses.slice(0, -1).join(", ")}` : undefined;
};

// `node browsers/deliver.ts chrome` runs one; no arguments runs them all.
const requested = process.argv.slice(2).map((name) => name.toLowerCase());
const selected = Object.entries(browsers).filter(
	([name]) => requested.length === 0 || requested.includes(name.toLowerCase()),
);
if (selected.length === 0) {
	throw new Error(
		`No browser matches ${requested.join(", ")}; known: ${Object.keys(browsers).join(", ")}`,
	);
}

const results: CheckResult[] = [];
for (const [name, launch] of selected) {
	const profileDir = await mkdtemp(join(tmpdir(), `web-push-${name}-`));
	let context: BrowserContext | undefined;
	try {
		context = await launch(profileDir);
		const note = await deliverTo(context);
		results.push({ name: `${name} receives and decrypts a push`, passed: true, detail: note });
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
