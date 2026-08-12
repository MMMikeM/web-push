import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import {
	createVapidJwt,
	generateVapidKeys,
	uint8ArrayToUrlBase64,
	urlBase64ToUint8Array,
} from "../src/vapid";
import { decodeJwtSegment, verifyJwtSignature } from "./helpers";

afterEach(() => {
	vi.restoreAllMocks();
});

describe("urlBase64ToUint8Array", () => {
	it("returns an empty array for an empty string", () => {
		expect(urlBase64ToUint8Array("")).toEqual(new Uint8Array(0));
	});

	it("decodes a known unpadded value", () => {
		expect(new TextDecoder().decode(urlBase64ToUint8Array("SGVsbG8"))).toBe("Hello");
	});

	it("adds padding for lengths that are 2 or 3 mod 4", () => {
		expect(new TextDecoder().decode(urlBase64ToUint8Array("TWE"))).toBe("Ma");
		expect(new TextDecoder().decode(urlBase64ToUint8Array("TQ"))).toBe("M");
	});

	it("maps URL-safe chars '-' and '_' back to '+' and '/'", () => {
		// 0xFB 0xFF 0xBF encodes to "+/+/" in std base64 and "-_-_" URL-safe.
		const bytes = urlBase64ToUint8Array("-_-_");
		expect(Array.from(bytes)).toEqual([0xfb, 0xff, 0xbf]);
	});

	it("throws on characters outside the base64url alphabet", () => {
		expect(() => urlBase64ToUint8Array("@@@@")).toThrow("Invalid character");
	});

	it("throws on a length that no base64 encoding can produce (1 mod 4)", () => {
		expect(() => urlBase64ToUint8Array("AQIDA")).toThrow("Invalid character");
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

	it("strips the padding std base64 adds for 1- and 2-mod-3 lengths", () => {
		expect(uint8ArrayToUrlBase64(new Uint8Array([0x01]))).toBe("AQ"); // std: "AQ=="
		expect(uint8ArrayToUrlBase64(new Uint8Array([0x01, 0x02]))).toBe("AQI"); // std: "AQI="
	});

	it("round-trips arbitrary bytes", () => {
		const original = crypto.getRandomValues(new Uint8Array(200));
		expect(urlBase64ToUint8Array(uint8ArrayToUrlBase64(original))).toEqual(original);
	});

	it("round-trips random bytes at every length 0-66", () => {
		// Covers every length mod 3 / mod 4 class — the fixed vectors cluster on
		// lengths that never pad, which is how the padding-strip mutant survived.
		for (let length = 0; length <= 66; length++) {
			const bytes = crypto.getRandomValues(new Uint8Array(length));
			const encoded = uint8ArrayToUrlBase64(bytes);
			expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
			expect(urlBase64ToUint8Array(encoded)).toEqual(bytes);
		}
	});

	it("encodes a large array without a stack overflow", () => {
		// String.fromCharCode(...array) throws RangeError past ~100k elements.
		// (getRandomValues caps at 65536 bytes, so fill deterministically.)
		const big = new Uint8Array(200_000);
		for (let i = 0; i < big.length; i++) big[i] = i % 256;
		const encoded = uint8ArrayToUrlBase64(big);
		// A string round-trip, not a 200k-element toEqual — the deep compare costs
		// ~270ms of assertion overhead for identical coverage.
		expect(uint8ArrayToUrlBase64(urlBase64ToUint8Array(encoded))).toBe(encoded);
	});
});

describe("generateVapidKeys", () => {
	it("throws if the runtime exports a private key without its scalar", async () => {
		const realExport = crypto.subtle.exportKey.bind(crypto.subtle);
		vi.spyOn(crypto.subtle, "exportKey").mockImplementation(
			async (format: KeyFormat, key: CryptoKey) =>
				format === "jwk" ? {} : realExport(format as "raw", key),
		);
		await expect(generateVapidKeys()).rejects.toThrow(
			"Generated P-256 key exported without a private scalar",
		);
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

		expect(jwt.split(".")).toHaveLength(3);
		const [h, p] = jwt.split(".");

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
		const after = Math.floor(Date.now() / 1000);
		const claims = decodeJwtSegment(jwt.split(".")[1]) as { exp: number };
		expect(claims.exp).toBeGreaterThanOrEqual(before + 43200);
		expect(claims.exp).toBeLessThanOrEqual(after + 43200);
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

	it.each([0, -3600])("rejects a non-positive expiration (%i)", async (expiration) => {
		const { publicKey, privateKey } = await generateVapidKeys();
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "mailto:a@b.com",
				publicKey,
				privateKey,
				expiration,
			}),
		).rejects.toThrow("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");
	});

	it("accepts an expiration of exactly 24 hours (86400s)", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		const jwt = await createVapidJwt({
			audience: "https://example.com",
			subject: "mailto:a@b.com",
			publicKey,
			privateKey,
			expiration: 86400,
		});
		expect(jwt.split(".")).toHaveLength(3);
	});

	it("accepts an https:// subject", async () => {
		const { publicKey, privateKey } = await generateVapidKeys();
		const jwt = await createVapidJwt({
			audience: "https://example.com",
			subject: "https://example.com/contact",
			publicKey,
			privateKey,
		});
		expect(decodeJwtSegment(jwt.split(".")[1]).sub).toBe("https://example.com/contact");
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

	it("rejects a 65-byte public key without the 0x04 uncompressed prefix", async () => {
		const { privateKey } = await generateVapidKeys();
		const compressedPrefix = new Uint8Array(65);
		compressedPrefix[0] = 0x02;
		await expect(
			createVapidJwt({
				audience: "https://example.com",
				subject: "mailto:a@b.com",
				publicKey: uint8ArrayToUrlBase64(compressedPrefix),
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
