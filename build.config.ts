import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
	entries: ["./src/index", "./src/vapid", "./src/send", "./src/client"],
	declaration: true,
	clean: true,
	rollup: {
		emitCJS: false,
	},
});
