import { describe, expect, it, vi } from "vite-plus/test";
import {
	createVapidJwt,
	generateVapidKeys,
	uint8ArrayToUrlBase64,
	urlBase64ToUint8Array,
} from "../src/vapid";
import { decodeJwtSegment } from "./helpers";

/** Verify a JWT's ES256 signature against a URL-safe base64 P-256 public key. */
const verifyJwtSignature = async (jwt: string, publicKey: string): Promise<boolean> => {
	const [header, claims, signature] = jwt.split(".");
	const verifyKey = await crypto.subtle.importKey(
		"raw",
		urlBase64ToUint8Array(publicKey),
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["verify"],
	);
	return crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		verifyKey,
		urlBase64ToUint8Array(signature),
		new TextEncoder().encode(`${header}.${claims}`),
	);
};

describe("urlBase64ToUint8Array", () => {
	it("returns an empty array for an empty string", () => {
		expect(urlBase64ToUint8Array("")).toEqual(new Uint8Array(0));
	});

	it("decodes a known unpadded value", () => {
		expect(new TextDecoder().decode(urlBase64ToUint8Array("SGVsbG8"))).toBe("Hello");
	});

	it("adds padding for lengths that are 2 or 3 mod 4", () => {
		expect(new TextDecoder().decode(urlBase64ToUint8Array("TWE"))).toBe("Ma"); // len 3
		expect(new TextDecoder().decode(urlBase64ToUint8Array("TQ"))).toBe("M"); // len 2
	});

	it("maps URL-safe chars '-' and '_' back to '+' and '/'", () => {
		// 0xFB 0xFF 0xBF encodes to "+/+/" in std base64 and "-_-_" URL-safe.
		const bytes = urlBase64ToUint8Array("-_-_");
		expect(Array.from(bytes)).toEqual([0xfb, 0xff, 0xbf]);
	});
});

describe("uint8ArrayToUrlBase64", () => {
	it("produces URL-safe output with no '=' padding", () => {
		const out = uint8ArrayToUrlBase64(new Uint8Array([0xfb, 0xff, 0xbf]));
		expect(out).toBe("-_-_");
		expect(out).not.toContain("=");
		expect(out).not.toContain("+");
		expect(out).not.toContain("/");
	});

	it("round-trips arbitrary bytes", () => {
		const original = crypto.getRandomValues(new Uint8Array(200));
		expect(urlBase64ToUint8Array(uint8ArrayToUrlBase64(original))).toEqual(original);
	});

	it("encodes a large array without a stack overflow", () => {
		// String.fromCharCode(...array) throws RangeError past ~100k elements.
		// (getRandomValues caps at 65536 bytes, so fill deterministically.)
		const big = new Uint8Array(200_000);
		for (let i = 0; i < big.length; i++) big[i] = i % 256;
		const encoded = uint8ArrayToUrlBase64(big);
		expect(urlBase64ToUint8Array(encoded)).toEqual(big);
	});
});

describe("generateVapidKeys", () => {
	it("throws if the runtime exports a private key without its scalar", async () => {
		const realExport = crypto.subtle.exportKey.bind(crypto.subtle);
		const spy = vi
			.spyOn(crypto.subtle, "exportKey")
			.mockImplementation(async (format: KeyFormat, key: CryptoKey) =>
				format === "jwk" ? {} : realExport(format as "raw", key),
			);
		await expect(generateVapidKeys()).rejects.toThrow(
			"Generated P-256 key exported without a private scalar",
		);
		spy.mockRestore();
	});

	it("returns a 65-byte uncompressed public key and 32-byte private scalar", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();

		const pub = urlBase64ToUint8Array(publicKey);
		expect(pub.length).toBe(65);
		expect(pub[0]).toBe(0x04); // uncompressed point prefix

		const priv = urlBase64ToUint8Array(privateKey);
		expect(priv.length).toBe(32);
	});

	it("produces a public key importable into Web Crypto as ECDSA P-256", async () => {
		const { publicKey } = await generateVapidKeys();
		await expect(
			crypto.subtle.importKey(
				"raw",
				urlBase64ToUint8Array(publicKey),
				{ name: "ECDSA", namedCurve: "P-256" },
				false,
				["verify"],
			),
		).resolves.toBeDefined();
	});

	it("returns a distinct pair each call", async () => {
		const a = await generateVapidKeys();
		const b = await generateVapidKeys();
		expect(a.publicKey).not.toBe(b.publicKey);
		expect(a.privateKey).not.toBe(b.privateKey);
	});
});

describe("createVapidJwt", () => {
	it("builds a three-segment JWT with the expected header and claims", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		const before = Math.floor(Date.now() / 1000);
		const jwt = await createVapidJwt({
			audience: "https://fcm.googleapis.com",
			subject: "mailto:admin@example.com",
			publicKey,
			privateKey,
			expiration: 3600,
		});
		const after = Math.floor(Date.now() / 1000);

		const [h, p, s] = jwt.split(".");
		expect(h && p && s).toBeTruthy();

		expect(decodeJwtSegment(h)).toEqual({ typ: "JWT", alg: "ES256" });

		const claims = decodeJwtSegment(p) as { aud: string; exp: number; sub: string };
		expect(claims.aud).toBe("https://fcm.googleapis.com");
		expect(claims.sub).toBe("mailto:admin@example.com");
		expect(claims.exp).toBeGreaterThanOrEqual(before + 3600);
		expect(claims.exp).toBeLessThanOrEqual(after + 3600);
	});

	it("defaults expiration to 12 hours (43200s)", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		const before = Math.floor(Date.now() / 1000);
		const jwt = await createVapidJwt({
			audience: "https://example.com",
			subject: "mailto:a@b.com",
			publicKey,
			privateKey,
		});
		const claims = decodeJwtSegment(jwt.split(".")[1]) as { exp: number };
		expect(claims.exp).toBeGreaterThanOrEqual(before + 43200);
		expect(claims.exp).toBeLessThanOrEqual(before + 43200 + 5);
	});

	it("produces a signature verifiable with the VAPID public key", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		const jwt = await createVapidJwt({
			audience: "https://example.com",
			subject: "mailto:a@b.com",
			publicKey,
			privateKey,
		});

		expect(await verifyJwtSignature(jwt, publicKey)).toBe(true);
	});

	it("rejects an expiration greater than 24 hours", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "mailto:a@b.com",
				publicKey,
				privateKey,
				expiration: 86401,
			}),
		).rejects.toThrow("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");
	});

	it("rejects a subject that is not a mailto:/https: URI", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "admin@example.com",
				publicKey,
				privateKey,
			}),
		).rejects.toThrow("VAPID subject must be a 'mailto:' or 'https://' URI");
	});

	it("rejects a malformed public key", async () => {
		const { privateKey } = await generateVapidKeys();
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "mailto:a@b.com",
				publicKey: uint8ArrayToUrlBase64(new Uint8Array(10)),
				privateKey,
			}),
		).rejects.toThrow("VAPID public key must be a 65-byte uncompressed P-256 point");
	});

	it("rejects a malformed private key", async () => {
		const { publicKey } = await generateVapidKeys();
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "mailto:a@b.com",
				publicKey,
				privateKey: uint8ArrayToUrlBase64(new Uint8Array(10)),
			}),
		).rejects.toThrow("VAPID private key must be a 32-byte P-256 scalar");
	});

	it("fails verification against a different public key", async () => {
		const signer = await generateVapidKeys();
		const other = await generateVapidKeys();
		const jwt = await createVapidJwt({
			audience: "https://example.com",
			subject: "mailto:a@b.com",
			publicKey: signer.publicKey,
			privateKey: signer.privateKey,
		});
		expect(await verifyJwtSignature(jwt, other.publicKey)).toBe(false);
	});
});
