/**
 * Shared test helpers. The receiver side, which decrypts and verifies what the
 * library sends, lives in `receiver.ts` so the runtime conformance script can
 * load it without vitest.
 */

import { Mock, vi } from "vite-plus/test";

export {
	decodeJwtSegment,
	decryptAes128gcm,
	makeClientKeys,
	vapidJwtFromAuthorization,
	verifyJwtSignature,
	type ClientKeys,
} from "./receiver";

/** Stub global `fetch` to resolve with the given response; returns the mock. */
export const stubFetch = (
	status = 201,
	statusText = "",
	headers?: Record<string, string>,
): Mock<(_input: string | URL | Request, _init?: RequestInit) => Promise<Response>> => {
	// 204/304/1xx must be constructed with a null body or Response throws.
	const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);
	// The explicit type parameter keeps `mock.calls` a two-element tuple; without
	// it the tuple types as empty and every `calls[0][1]` fails to compile.
	const mock = vi.fn<(input: string | URL | Request, init?: RequestInit) => Promise<Response>>(
		async () => new Response(noBody ? null : "err-body", { status, statusText, headers }),
	);
	vi.stubGlobal("fetch", mock);
	return mock;
};

/** The headers of the first `fetch` call, as the plain record the library passes. */
export const headersOf = (mock: ReturnType<typeof stubFetch>): Record<string, string> =>
	(mock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
