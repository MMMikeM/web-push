import {
	rawPayload,
	sendPushBatch,
	sendPushNotification,
	WebPushError,
} from "@mmmike/web-push/send";
import { generateVapidKeys } from "@mmmike/web-push/vapid";
import {
	decodeJwtSegment,
	decryptAes128gcm,
	fromBase64Url,
	makeClientKeys,
	toBase64Url,
	vapidJwtFromAuthorization,
	verifyJwtSignature,
} from "../../test/receiver.ts";

/** One check's outcome, as printed by every runtime's runner. */
export type CheckResult = { name: string; passed: boolean; detail?: string };

type SentRequest = { url: string; headers: Record<string, string>; body: Uint8Array };

const ENDPOINT = "https://push.example.com/send/conformance";
const SUBJECT = "mailto:conformance@example.com";

/** Answer every `fetch` with `statusFor(url)` while `run` executes, recording the requests. */
const withStubbedFetch = async <T>(
	statusFor: (url: string) => number,
	run: (sent: SentRequest[]) => Promise<T>,
): Promise<T> => {
	const sent: SentRequest[] = [];
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const url = String(input);
		sent.push({
			url,
			headers: init?.headers as Record<string, string>,
			body: init?.body as Uint8Array,
		});
		return new Response(null, { status: statusFor(url) });
	};
	try {
		return await run(sent);
	} finally {
		globalThis.fetch = realFetch;
	}
};

const expectEqual = (actual: unknown, expected: unknown, what: string): void => {
	if (actual !== expected) {
		throw new Error(`${what}: expected ${String(expected)}, got ${String(actual)}`);
	}
};

// RFC 8291 Appendix A, copied verbatim: https://www.rfc-editor.org/rfc/rfc8291#appendix-A
const RFC = {
	plaintext: "When I grow up, I want to be a watermelon",
	uaPublic:
		"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
	authSecret: "BTBZMqHH6r4Tts7J_aSIgg",
	asPrivate: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
	asPublic:
		"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
	salt: "DGv6ra1nlYgDCS1FRnbzlw",
	body:
		"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
		"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
		"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
};

/** The RFC's application server key pair; the private half goes in as a JWK, as Web Crypto has no raw ECDH private import. */
const importRfcServerKeyPair = async (): Promise<CryptoKeyPair> => {
	const publicBytes = fromBase64Url(RFC.asPublic);
	const algorithm = { name: "ECDH", namedCurve: "P-256" };
	const publicKey = await crypto.subtle.importKey("raw", publicBytes, algorithm, true, []);
	const privateKey = await crypto.subtle.importKey(
		"jwk",
		{
			kty: "EC",
			crv: "P-256",
			x: toBase64Url(publicBytes.slice(1, 33)),
			y: toBase64Url(publicBytes.slice(33, 65)),
			d: RFC.asPrivate,
		},
		algorithm,
		false,
		["deriveBits"],
	);
	return { publicKey, privateKey };
};

/**
 * Run `run` with the RFC's fixed ephemeral key pair and salt in place of fresh
 * random ones. The published package has no seam for them, by design, so the
 * Web Crypto calls it makes are swapped out underneath it instead.
 */
const withRfcRandomness = async <T>(run: () => Promise<T>): Promise<T> => {
	const keyPair = await importRfcServerKeyPair();
	const salt = fromBase64Url(RFC.salt);
	const { subtle } = crypto;
	const realGenerateKey = subtle.generateKey;
	const realGetRandomValues = crypto.getRandomValues;
	const replace = (target: object, name: string, value: unknown) =>
		Object.defineProperty(target, name, { value, configurable: true, writable: true });

	replace(
		subtle,
		"generateKey",
		(algorithm: AlgorithmIdentifier & { name?: string }, ...rest: never[]) =>
			algorithm.name === "ECDH"
				? Promise.resolve(keyPair)
				: Reflect.apply(realGenerateKey, subtle, [algorithm, ...rest]),
	);
	replace(crypto, "getRandomValues", <A extends ArrayBufferView | null>(array: A): A => {
		if (array instanceof Uint8Array && array.length === salt.length) {
			array.set(salt);
			return array;
		}
		return Reflect.apply(realGetRandomValues, crypto, [array]);
	});
	try {
		return await run();
	} finally {
		replace(subtle, "generateKey", realGenerateKey);
		replace(crypto, "getRandomValues", realGetRandomValues);
	}
};

const checks: Record<string, () => Promise<void>> = {
	"encrypts the RFC 8291 Appendix A example byte for byte": async () => {
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const subscription = {
			endpoint: ENDPOINT,
			keys: { p256dh: RFC.uaPublic, auth: RFC.authSecret },
		};
		const [request] = await withStubbedFetch(
			() => 201,
			async (sent) => {
				await withRfcRandomness(() =>
					sendPushNotification(subscription, rawPayload(RFC.plaintext), vapid),
				);
				return sent;
			},
		);
		expectEqual(toBase64Url(request.body), RFC.body, "request body");
	},

	"encrypts a payload an independent receiver decrypts": async () => {
		const client = await makeClientKeys();
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const payload = { title: "Conformance", body: "ünïcödé ✓" };
		const [request] = await withStubbedFetch(
			() => 201,
			async (sent) => {
				await sendPushNotification(
					{ endpoint: ENDPOINT, keys: { p256dh: client.p256dh, auth: client.auth } },
					payload,
					vapid,
				);
				return sent;
			},
		);
		const plaintext = new TextDecoder().decode(await decryptAes128gcm(request.body, client));
		expectEqual(plaintext, JSON.stringify(payload), "decrypted payload");
	},

	"signs a VAPID JWT that verifies against its public key (RFC 8292)": async () => {
		const client = await makeClientKeys();
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const [request] = await withStubbedFetch(
			() => 201,
			async (sent) => {
				await sendPushNotification(
					{ endpoint: ENDPOINT, keys: { p256dh: client.p256dh, auth: client.auth } },
					{ title: "jwt" },
					vapid,
				);
				return sent;
			},
		);
		const authorization = request.headers.Authorization;
		expectEqual(
			authorization.endsWith(`, k=${vapid.publicKey}`),
			true,
			"k= carries the public key",
		);
		const jwt = vapidJwtFromAuthorization(authorization);
		expectEqual(await verifyJwtSignature(jwt, vapid.publicKey), true, "ES256 signature verifies");
		const claims = decodeJwtSegment(jwt.split(".")[1]);
		expectEqual(claims.aud, new URL(ENDPOINT).origin, "aud claim");
		expectEqual(claims.sub, SUBJECT, "sub claim");
		const secondsLeft = Number(claims.exp) - Date.now() / 1000;
		expectEqual(secondsLeft > 0 && secondsLeft <= 24 * 60 * 60, true, "exp within 24 hours");
	},

	"sends the RFC 8030 and RFC 8188 headers": async () => {
		const client = await makeClientKeys();
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const [request] = await withStubbedFetch(
			() => 201,
			async (sent) => {
				await sendPushNotification(
					{ endpoint: ENDPOINT, keys: { p256dh: client.p256dh, auth: client.auth } },
					{ title: "headers" },
					vapid,
					{ ttl: 60, urgency: "high", topic: "conformance" },
				);
				return sent;
			},
		);
		expectEqual(request.headers["Content-Encoding"], "aes128gcm", "Content-Encoding");
		expectEqual(request.headers.TTL, "60", "TTL");
		expectEqual(request.headers.Urgency, "high", "Urgency");
		expectEqual(request.headers.Topic, "conformance", "Topic");
	},

	"resolves false for a subscription the push service reports gone": async () => {
		const client = await makeClientKeys();
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const delivered = await withStubbedFetch(
			() => 410,
			() =>
				sendPushNotification(
					{ endpoint: ENDPOINT, keys: { p256dh: client.p256dh, auth: client.auth } },
					{ title: "gone" },
					vapid,
				),
		);
		expectEqual(delivered, false, "result for a 410");
	},

	"sorts a batch into delivered, gone and failed": async () => {
		const vapid = { ...(await generateVapidKeys()), subject: SUBJECT };
		const statusByPath: Record<string, number> = { "/ok": 201, "/gone": 404, "/error": 500 };
		const subscriptions = await Promise.all(
			Object.keys(statusByPath).map(async (path) => {
				const client = await makeClientKeys();
				return {
					endpoint: `${ENDPOINT}${path}`,
					keys: { p256dh: client.p256dh, auth: client.auth },
				};
			}),
		);
		const result = await withStubbedFetch(
			(url) => statusByPath[new URL(url).pathname.replace("/send/conformance", "")] ?? 599,
			() => sendPushBatch(subscriptions, { title: "batch" }, vapid),
		);
		expectEqual(result.delivered, 1, "delivered");
		expectEqual(result.gone.join(), `${ENDPOINT}/gone`, "gone");
		const [failure] = result.failed;
		expectEqual(failure?.endpoint, `${ENDPOINT}/error`, "failed endpoint");
		expectEqual(
			failure?.error instanceof WebPushError && failure.error.statusCode,
			500,
			"failed error status",
		);
	},
};

/** Run every check in turn; a failure is recorded, never thrown. */
export const runChecks = async (): Promise<CheckResult[]> => {
	const results: CheckResult[] = [];
	for (const [name, check] of Object.entries(checks)) {
		try {
			await check();
			results.push({ name, passed: true });
		} catch (error) {
			results.push({ name, passed: false, detail: String(error) });
		}
	}
	return results;
};

/** One line per check, then a summary naming the runtime. */
export const report = (results: CheckResult[], runtime: string): string => {
	const lines = results.map(
		({ name, passed, detail }) =>
			`${passed ? "ok  " : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`,
	);
	const failed = results.filter(({ passed }) => !passed).length;
	lines.push(
		failed === 0
			? `${results.length} checks passed on ${runtime}`
			: `${failed} of ${results.length} checks failed on ${runtime}`,
	);
	return lines.join("\n");
};
