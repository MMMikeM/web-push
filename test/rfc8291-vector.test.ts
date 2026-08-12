import { describe, expect, it } from "vite-plus/test";
import { encryptRecord } from "../src/encrypt";
import { uint8ArrayToUrlBase64, urlBase64ToUint8Array } from "../src/vapid";

/**
 * RFC 8291 Appendix A known-answer test.
 *
 * The round-trip suite proves sender and (test-helper) receiver agree with
 * each other; this vector proves they agree with the RFC. Every value below
 * is copied verbatim from https://www.rfc-editor.org/rfc/rfc8291#appendix-A.
 */

const PLAINTEXT = "When I grow up, I want to be a watermelon";

// Receiver (user agent) keys — what a real subscription would hand the sender.
const UA_PUBLIC =
	"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH_SECRET = "BTBZMqHH6r4Tts7J_aSIgg";

// Application server ephemeral key pair and salt — random per message in
// production, passed to encryptRecord explicitly here so the vector reproduces.
const AS_PRIVATE = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
const AS_PUBLIC =
	"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
const SALT = "DGv6ra1nlYgDCS1FRnbzlw";

const EXPECTED_BODY =
	"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
	"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
	"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

/** The RFC's fixed AS key pair — the private half via JWK, since WebCrypto has no raw ECDH private import. */
const importAsKeyPair = async (): Promise<CryptoKeyPair> => {
	const publicBytes = urlBase64ToUint8Array(AS_PUBLIC);
	const publicKey = await crypto.subtle.importKey(
		"raw",
		publicBytes,
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		[],
	);
	// Raw P-256 public key is 0x04 || x (32) || y (32).
	const privateKey = await crypto.subtle.importKey(
		"jwk",
		{
			kty: "EC",
			crv: "P-256",
			x: uint8ArrayToUrlBase64(publicBytes.slice(1, 33)),
			y: uint8ArrayToUrlBase64(publicBytes.slice(33, 65)),
			d: AS_PRIVATE,
		},
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		["deriveBits"],
	);
	return { publicKey, privateKey };
};

describe("RFC 8291 Appendix A vector", () => {
	it("produces the RFC's ciphertext byte-for-byte", async () => {
		const keyPair = await importAsKeyPair();
		const salt = urlBase64ToUint8Array(SALT);
		const payload = new TextEncoder().encode(PLAINTEXT);

		const body = await encryptRecord(payload, UA_PUBLIC, AUTH_SECRET, keyPair, salt);

		expect(uint8ArrayToUrlBase64(body)).toBe(EXPECTED_BODY);
	});
});
