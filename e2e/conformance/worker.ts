import { runChecks } from "./checks.ts";

export default {
	fetch: async (): Promise<Response> =>
		Response.json({ runtime: navigator.userAgent, results: await runChecks() }),
};
