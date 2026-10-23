import { report, runChecks } from "./checks.ts";

const results = await runChecks();
console.log(report(results, navigator.userAgent));
if (results.some(({ passed }) => !passed)) {
	throw new Error("conformance checks failed");
}
