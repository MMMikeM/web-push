import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { format } from "oxfmt";
import { API, SignatureKind, SymbolFlags, TypeFlags, TypeFormatFlags } from "typescript/sync";
import type { Checker, Signature, Symbol, Type } from "typescript/sync";

type Page = { name: string; title: string; description: string; order: number };

const PAGES: Page[] = [
	{
		name: "client",
		title: "Client",
		description:
			"Browser helpers: feature detection, the permission prompt, subscribing, and syncing the subscription with your server.",
		order: 1,
	},
	{
		name: "send",
		title: "Send",
		description:
			"Server-side sending: encrypt, sign, and deliver one notification, or fan one out to many subscriptions.",
		order: 2,
	},
	{
		name: "vapid",
		title: "VAPID",
		description: "VAPID key generation, JWT signing, and the base64url codec they share.",
		order: 3,
	},
];
const ROOT = "index";
// Absolute, so links survive in the per-page Markdown and llms-full.txt, which
// are read away from the page they were written for. Matches astro.config.mjs.
const SITE_BASE = "/web-push";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");
const outDir = join(repoRoot, "docs/src/content/docs/reference");
const moduleFile = (module: string) => join(repoRoot, "src", `${module}.ts`);
const importPath = (module: string) =>
	module === ROOT ? "@mmmike/web-push" : `@mmmike/web-push/${module}`;

const api = new API({ cwd: repoRoot });
const { options } = api.parseConfigFile(join(repoRoot, "tsconfig.json"));
const modules = [ROOT, ...PAGES.map((page) => page.name)];
const program = api.createProgram(modules.map(moduleFile), options);
const checker: Checker = program.getProject().checker;

const resolveAlias = (symbol: Symbol) =>
	symbol.flags & SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;

// Every checker call is a round trip to the TypeScript process, and the same
// symbols are asked about many times over, so answers are cached.
const memoize = <K, V>(compute: (key: K) => V) => {
	const cache = new Map<K, V>();
	return (key: K): V => {
		if (!cache.has(key)) {
			cache.set(key, compute(key));
		}
		return cache.get(key) as V;
	};
};

const exportsOf = memoize((module: string) =>
	checker.getExportsOfModule(checker.getSymbolOfSourceFile(moduleFile(module))).map((symbol) => ({
		name: symbol.name,
		symbol: resolveAlias(symbol),
	})),
);

const exportedFrom = new Map<string, string[]>();
const home = new Map<string, string>();
const symbolOf = new Map<string, Symbol>();
for (const module of modules) {
	for (const { name, symbol } of exportsOf(module)) {
		symbolOf.set(name, symbol);
		exportedFrom.set(name, [...(exportedFrom.get(name) ?? []), module]);
		if (module !== ROOT && !home.has(name)) {
			home.set(name, module);
		}
	}
}
for (const name of exportedFrom.keys()) {
	if (!home.has(name)) {
		home.set(name, ROOT);
	}
}

// `RawPushPayload` aliases a private class, which the checker prints by its own
// name. Only object types qualify: `type Topic = string` would otherwise rename
// every `string`.
const exportedAliasOf = new Map<string, string>();
for (const [name, symbol] of symbolOf) {
	if (symbol.flags & SymbolFlags.TypeAlias) {
		const declared = checker.getDeclaredTypeOfSymbol(symbol);
		const shown = checker.typeToString(declared);
		const isObject = declared.flags & TypeFlags.Object;
		if (isObject && /^\w+$/.test(shown) && shown !== name && !symbolOf.has(shown)) {
			exportedAliasOf.set(shown, name);
		}
	}
}
// Browser types the API mentions, such as `NotificationPermission`, get an
// entry under "Browser types" on the overview, and every mention links there.
type DomType = { symbol: Symbol; isAlias: boolean };
const domTypes = new Map<string, DomType | undefined>();
const domType = (name: string) => {
	if (!domTypes.has(name)) {
		const symbol = checker.resolveName(name, SymbolFlags.Type);
		const isDom =
			symbol &&
			symbol.flags & (SymbolFlags.TypeAlias | SymbolFlags.Interface) &&
			symbol.declarations.every((declaration) => declaration.path.endsWith("lib.dom.d.ts"));
		domTypes.set(
			name,
			isDom ? { symbol, isAlias: Boolean(symbol.flags & SymbolFlags.TypeAlias) } : undefined,
		);
	}
	return domTypes.get(name);
};
const usedDomTypes = new Set<string>();

const typeText = (type: Type) =>
	checker.typeToString(type).replace(/\b[A-Z]\w*\b/g, (word) => {
		if (domType(word)) {
			usedDomTypes.add(word);
		}
		return exportedAliasOf.get(word) ?? word;
	});

const anchor = (name: string) => name.toLowerCase();
const hrefFor = (name: string) => {
	const target = home.get(name);
	const page = target === ROOT ? "" : `${target}/`;
	return target && `${SITE_BASE}/reference/${page}#${anchor(name)}`;
};

const linkify = (text: string) =>
	text.replace(/\{@link\s+([\w.]+)(?:[\s|]+([^}]+))?\}/g, (_, name: string, label?: string) => {
		const href = hrefFor(name.split(".")[0] ?? name);
		const shown = label?.trim() ?? `\`${name}\``;
		return href ? `[${shown}](${href})` : shown;
	});

type JSDocHost = { jsDoc?: readonly { getText(): string }[]; parent?: JSDocHost };

// The checker's documentation text flattens `{@link X}` to `X`, losing the
// target, and drops the line break after one inside a tag, so docs come from
// the raw comment. A `const` function's JSDoc sits on its variable statement,
// two levels above the declaration; nothing else climbs, or a field without
// docs would borrow its enclosing type's.
const rawJsDoc = (symbol: Symbol) => {
	const levels = symbol.flags & SymbolFlags.Variable ? 3 : 1;
	let node = symbol.declarations[0]?.resolve() as JSDocHost | undefined;
	for (let depth = 0; node && depth < levels; depth++, node = node.parent) {
		const comment = node.jsDoc?.at(-1)?.getText();
		if (comment) {
			return comment;
		}
	}
	return undefined;
};

const rawSections = memoize((symbol: Symbol) => {
	const comment = rawJsDoc(symbol);
	if (!comment) {
		return undefined;
	}
	const body = comment
		.replace(/^\/\*\*|\*\/$/g, "")
		.split("\n")
		.map((line) => line.replace(/^\s*\* ?/, ""))
		.join("\n");
	const [text = "", ...tags] = `\n${body.trim()}`.split(/\n(?=@)/);
	return {
		text: text.trim(),
		tags: tags.map((tag) => {
			const [, name = "", rest = ""] = /^@(\w+)\s*([\s\S]*)$/.exec(tag.trim()) ?? [];
			return { name, text: rest.trim() };
		}),
	};
});

const description = (symbol: Symbol) =>
	rawSections(symbol)?.text ?? checker.getDocumentationCommentOfSymbol(symbol);

const tableCell = (text: string) => text.replaceAll("|", "\\|").replaceAll("\n", " ");

// A row typed by one of the library's own types, and with no doc of its own,
// borrows that type's summary rather than leaving the cell blank.
const typeSummary = (type: string) => {
	const element = /^(?:readonly )?(\w+)\[\]$/.exec(type)?.[1];
	const target = symbolOf.get(element ?? type);
	if (!target) {
		return "";
	}
	const summary = firstSentence(description(target));
	return element ? `Each one is ${summary.charAt(0).toLowerCase()}${summary.slice(1)}` : summary;
};

const typeHrefs = new Map<string, string | undefined>();
const typeHref = (name: string) => {
	if (!typeHrefs.has(name)) {
		const href = exportedFrom.has(name)
			? hrefFor(name)
			: domType(name) && `${SITE_BASE}/reference/#${anchor(name)}`;
		typeHrefs.set(name, href);
	}
	return typeHrefs.get(name);
};

// Markdown can't link inside a code span, so a composite type becomes linked
// names joined by code spans for the rest. In a table every `|` is escaped,
// code spans included: GFM splits cells on a raw one wherever it appears.
// Outside a table the escape would show, so it is left out.
const typeCell = (type: string, inTable = true) =>
	type
		.split(/(\b\w+\b)/)
		.reduce<{ name?: string; text: string }[]>((pieces, token) => {
			const href = /^\w+$/.test(token) ? typeHref(token) : undefined;
			const last = pieces.at(-1);
			if (href) {
				pieces.push({ name: token, text: `[\`${token}\`](${href})` });
			} else if (last && !last.name) {
				last.text += token;
			} else {
				pieces.push({ text: token });
			}
			return pieces;
		}, [])
		.map(({ name, text }) => {
			if (name) {
				return text;
			}
			const [, before = "", core = "", after = ""] = /^(\s*)([\s\S]*?)(\s*)$/.exec(text) ?? [];
			const pipe = inTable ? "\\|" : "|";
			const shown = core === "|" ? pipe : core && `\`${core.replaceAll("|", pipe)}\``;
			return `${before}${shown}${after}`;
		})
		.join("");
const fenced = (code: string) =>
	code.trimStart().startsWith("```") ? code : `\`\`\`ts\n${code}\n\`\`\``;

const tagsOf = (symbol: Symbol, tagName: string) =>
	(rawSections(symbol)?.tags ?? checker.getJsDocTagsOfSymbol(symbol))
		.filter((tag) => tag.name === tagName)
		.map((tag) => tag.text ?? "");

const paramDocs = (symbol: Symbol) =>
	new Map(
		tagsOf(symbol, "param").map((text) => {
			const [, name = "", description = ""] = /^(\S+)\s*(?:-\s*)?([\s\S]*)$/.exec(text) ?? [];
			return [name, description];
		}),
	);

const isOptionalParameter = (parameter: Symbol) => {
	const declaration = parameter.declarations[0]?.resolve() as
		| { questionToken?: unknown; initializer?: unknown }
		| undefined;
	return Boolean(declaration?.questionToken ?? declaration?.initializer);
};

const parameterName = (parameter: Symbol) =>
	parameter.name.startsWith("__") ? "options" : parameter.name;

const parameterList = (signature: Signature) =>
	signature
		.getParameters()
		.map((parameter) => {
			const optional = isOptionalParameter(parameter) ? "?" : "";
			const type = typeText(checker.getTypeOfSymbol(parameter));
			return `${parameterName(parameter)}${optional}: ${type}`;
		})
		.join(", ");

const functionDeclaration = (name: string, signature: Signature) =>
	`function ${name}(${parameterList(signature)}): ${typeText(signature.getReturnType())};`;

const classDeclaration = (symbol: Symbol, constructors: readonly Signature[]) => {
	const header = /^[^{]*/.exec(symbol.declarations[0]?.resolve()?.getText() ?? "")?.[0] ?? "";
	const heritage = header.replace(/^(export\s+)?class\s+\w+/, "").trim();
	const members = constructors.map((signature) => `constructor(${parameterList(signature)});`);
	return `declare class ${symbol.name}${heritage ? ` ${heritage}` : ""} {\n${members.join("\n")}\n}`;
};

const parameterTable = (symbol: Symbol, signature: Signature) => {
	const docs = paramDocs(symbol);
	const rows = signature.getParameters().flatMap((parameter): FieldDoc[] => {
		const name = parameterName(parameter);
		const parameterType = checker.getNonNullableType(checker.getTypeOfSymbol(parameter));
		const fields = fieldDocs(
			checker.getPropertiesOfType(parameterType).filter(declaredInLibrary),
			`${name}.`,
		);
		return [
			{
				field: `${name}${isOptionalParameter(parameter) ? "?" : ""}`,
				type: typeText(parameterType),
				description: linkify(
					docs.get(parameter.name) || docs.get(name) || typeSummary(typeText(parameterType)),
				),
			},
			...(fields.some((field) => field.description) ? fields : []),
		];
	});
	if (!rows.some((row) => row.description)) {
		return [];
	}
	return memberTable("Parameter", rows);
};

type FieldDoc = { field: string; type: string; description: string };

// `(…) => void` prints parenthesised inside `… | undefined`; once that's gone,
// so are the parentheses, if they wrap the whole type.
const unwrapParens = (type: string) => {
	if (!type.startsWith("(") || !type.endsWith(")")) {
		return type;
	}
	let depth = 0;
	for (let index = 0; index < type.length - 1; index++) {
		depth += type[index] === "(" ? 1 : type[index] === ")" ? -1 : 0;
		if (depth === 0) {
			return type;
		}
	}
	return type.slice(1, -1);
};

// An inline object type gets a row per nested field, so their docs survive.
const fieldDocs = (properties: readonly Symbol[], prefix = ""): FieldDoc[] =>
	properties.flatMap((property) => {
		const optional = Boolean(property.flags & SymbolFlags.Optional);
		const propertyType = checker.getTypeOfSymbol(property);
		const type = typeText(propertyType);
		const field = `${prefix}${property.name}${optional ? "?" : ""}`;
		const shownType = optional ? unwrapParens(type.replace(/ \| undefined$/, "")) : type;
		const isObjectLiteral = /^\{[\s\S]*\}$/.test(shownType);
		const nested = isObjectLiteral
			? fieldDocs(
					checker.getPropertiesOfType(propertyType).filter(declaredInLibrary),
					`${prefix}${property.name}.`,
				)
			: [];
		const documentedNested = nested.some((row) => row.description);
		return [
			{
				field,
				type: documentedNested ? "object" : shownType,
				description: linkify(description(property) || typeSummary(shownType)),
			},
			...(documentedNested ? nested : []),
		];
	});

const fieldTable = (properties: readonly Symbol[], heading = "Field") =>
	memberTable(heading, fieldDocs(properties));

// The name and its type share a column, stacked, so a long type wraps across
// half the table instead of a third.
const memberTable = (heading: string, rows: readonly FieldDoc[]) => {
	const described = rows.some((row) => row.description);
	const header = `${heading} <span class="member-type">Type</span>`;
	return [
		described ? `| ${header} | Description |` : `| ${header} |`,
		described ? "| --- | --- |" : "| --- |",
		...rows.map(({ field, type, description }) => {
			const member = `**\`${field}\`** <span class="member-type">${typeCell(type)}</span>`;
			return described ? `| ${member} | ${tableCell(description)} |` : `| ${member} |`;
		}),
	];
};

const declaredInLibrary = (symbol: Symbol) =>
	symbol.declarations.some((declaration) =>
		declaration.path.toLowerCase().startsWith(join(repoRoot, "src").toLowerCase()),
	);

// Signatures are code blocks, which can't hold links, so the return type is
// repeated here as a linked cell, ahead of what `@returns` says about it.
const commonSections = (name: string, symbol: Symbol, returnType?: string) => {
	const deprecated = tagsOf(symbol, "deprecated");
	const throws = tagsOf(symbol, "throws").map((text) => {
		const [, type, description = ""] = /^\{([^}]+)\}\s*([\s\S]*)$/.exec(text) ?? [];
		return `- ${type ? `\`${type}\` ` : ""}${linkify(type ? description : text).replaceAll("\n", " ")}`;
	});
	const returnsText = [...tagsOf(symbol, "returns"), ...tagsOf(symbol, "return")]
		.map((text) => linkify(text).replaceAll("\n", " "))
		.join(" ");
	const resolved = returnType && /^Promise<([\s\S]*)>$/.exec(returnType)?.[1];
	const linkedReturn = typeCell(resolved ?? returnType ?? "", false);
	const returns =
		returnsText || linkedReturn.includes("](")
			? [
					`**${resolved ? "Resolves to" : "Returns"}** ${linkedReturn}${returnsText ? ` — ${returnsText}` : ""}`,
					"",
				]
			: [];
	const examples = tagsOf(symbol, "example").map(fenced);
	const otherSubpaths = (exportedFrom.get(name) ?? [])
		.filter((module) => module !== ROOT && module !== home.get(name))
		.map((module) => `\`${importPath(module)}\``);
	return {
		before: deprecated.map((text) => `:::caution[Deprecated]\n${linkify(text)}\n:::\n`),
		after: [
			...returns,
			...(throws.length ? ["**Throws**", "", ...throws] : []),
			...(examples.length ? ["", "**Example**", "", ...examples] : []),
			...(otherSubpaths.length ? ["", `Also exported from ${otherSubpaths.join(" and ")}.`] : []),
			"",
		],
	};
};

const renderFunction = (name: string, symbol: Symbol) => {
	const signatures = checker.getSignaturesOfType(
		checker.getTypeOfSymbol(symbol),
		SignatureKind.Call,
	);
	const returnType = signatures[0] && typeText(signatures[0].getReturnType());
	const { before, after } = commonSections(name, symbol, returnType);
	return [
		`### \`${name}\``,
		"",
		...before,
		linkify(description(symbol)),
		"",
		fenced(signatures.map((signature) => functionDeclaration(name, signature)).join("\n")),
		"",
		...(isDeprecated(symbol) ? [] : parameterTable(symbol, signatures[0])),
		"",
		...after,
	];
};

const renderConstant = (name: string, symbol: Symbol) => {
	const { before, after } = commonSections(name, symbol);
	return [
		`### \`${name}\``,
		"",
		...before,
		linkify(description(symbol)),
		"",
		fenced(`const ${name}: ${typeText(checker.getTypeOfSymbol(symbol))};`),
		"",
		...after,
	];
};

const renderClass = (name: string, symbol: Symbol) => {
	const constructors = checker.getSignaturesOfType(
		checker.getTypeOfSymbol(symbol),
		SignatureKind.Construct,
	);
	const properties = checker
		.getPropertiesOfType(checker.getDeclaredTypeOfSymbol(symbol))
		.filter(declaredInLibrary);
	const { before, after } = commonSections(name, symbol);
	return [
		`### \`${name}\``,
		"",
		...before,
		linkify(description(symbol)),
		"",
		fenced(classDeclaration(symbol, constructors)),
		"",
		...fieldTable(properties, "Member"),
		"",
		...after,
	];
};

const renderType = (name: string, symbol: Symbol) => {
	const declared = checker.getDeclaredTypeOfSymbol(symbol);
	const isPlainObject = declared.flags & (TypeFlags.Object | TypeFlags.Intersection);
	const properties = isPlainObject ? checker.getPropertiesOfType(declared) : [];
	const fieldRows = fieldDocs(properties);
	const hasFieldDocs = fieldRows.some((row) => row.description);
	const isOpaque = [...exportedAliasOf.values()].includes(name);
	const declarationText = () =>
		fenced((symbol.declarations[0]?.resolve()?.getText() ?? "").replace(/^export\s+/, ""));
	const { before, after } = commonSections(name, symbol);
	return [
		`### \`${name}\``,
		"",
		...before,
		linkify(description(symbol)),
		"",
		...(hasFieldDocs ? memberTable("Field", fieldRows) : []),
		...(!hasFieldDocs && !isOpaque ? [declarationText()] : []),
		"",
		...after,
	];
};

const KINDS = ["Functions", "Classes", "Constants", "Types"] as const;
type Kind = (typeof KINDS)[number];

const kindOf = memoize((symbol: Symbol): Kind => {
	if (symbol.flags & SymbolFlags.Class) {
		return "Classes";
	}
	if (symbol.flags & (SymbolFlags.TypeAlias | SymbolFlags.Interface)) {
		return "Types";
	}
	const callable = checker.getSignaturesOfType(checker.getTypeOfSymbol(symbol), SignatureKind.Call);
	return callable.length ? "Functions" : "Constants";
});

const isDeprecated = (symbol: Symbol) => tagsOf(symbol, "deprecated").length > 0;

const undocumented: string[] = [];

const renderEntries = (page: string) => {
	const entries = exportsOf(page).filter(({ name }) => home.get(name) === page);
	for (const { name, symbol } of entries) {
		if (!description(symbol).trim()) {
			undocumented.push(`${importPath(page)}: ${name}`);
		}
	}
	const render = {
		Functions: renderFunction,
		Classes: renderClass,
		Constants: renderConstant,
		Types: renderType,
	};
	return KINDS.flatMap((kind) => {
		const ofKind = entries
			.filter(({ symbol }) => kindOf(symbol) === kind)
			.sort((a, b) => Number(isDeprecated(a.symbol)) - Number(isDeprecated(b.symbol)));
		return ofKind.length
			? [`## ${kind}`, "", ...ofKind.flatMap(({ name, symbol }) => render[kind](name, symbol))]
			: [];
	});
};

const frontmatter = (title: string, description: string, order: number) => [
	"---",
	`title: ${JSON.stringify(title)}`,
	`description: ${JSON.stringify(description)}`,
	"sidebar:",
	`  order: ${order}`,
	"---",
	"",
];

const firstSentence = (text: string) => text.split(/(?<=\.)\s|\n\n/)[0] ?? "";

const overviewSummary = (symbol: Symbol) => {
	const [deprecation] = tagsOf(symbol, "deprecated");
	return deprecation === undefined
		? firstSentence(description(symbol))
		: `**Deprecated.** ${firstSentence(deprecation)}`;
};

const overviewRow = (name: string, symbol: Symbol) =>
	`| [\`${name}\`](${hrefFor(name)}) | ${tableCell(linkify(overviewSummary(symbol)))} |`;

const entryTitle = (module: string) =>
	PAGES.find((page) => page.name === module)?.title ?? "Package root only";

const overviewSections = KINDS.flatMap((kind) => {
	const byEntryPoint = [...PAGES.map((page) => page.name), ROOT].flatMap((module) => {
		const rows = [...symbolOf.entries()]
			.filter(([name, symbol]) => kindOf(symbol) === kind && home.get(name) === module)
			.sort(
				([a, aSymbol], [b, bSymbol]) =>
					Number(isDeprecated(aSymbol)) - Number(isDeprecated(bSymbol)) || a.localeCompare(b),
			)
			.map(([name, symbol]) => overviewRow(name, symbol));
		return rows.length
			? [`### ${entryTitle(module)}`, "", "| Export | Summary |", "| --- | --- |", ...rows, ""]
			: [];
	});
	return byEntryPoint.length ? [`## ${kind}`, "", ...byEntryPoint] : [];
});

// Narrower than the repo's 100 columns, to fit the docs content column.
const formatCodeBlocks = async (markdown: string) => {
	const blocks = [...markdown.matchAll(/```ts\n([\s\S]*?)\n```/g)];
	const formatted = await Promise.all(
		blocks.map(async ([, code = ""]) => {
			const result = await format("snippet.ts", code, { useTabs: true, printWidth: 80 });
			return result.errors.length ? code : result.code.trimEnd();
		}),
	);
	let index = 0;
	return markdown.replace(/```ts\n[\s\S]*?\n```/g, () => `\`\`\`ts\n${formatted[index++]}\n\`\`\``);
};

const renderDomType = (name: string) => {
	const dom = domType(name);
	if (!dom) {
		return [];
	}
	const values = dom.isAlias
		? checker.typeToString(
				checker.getDeclaredTypeOfSymbol(dom.symbol),
				undefined,
				TypeFormatFlags.InTypeAlias,
			)
		: undefined;
	const text = description(dom.symbol);
	const mdn = `https://developer.mozilla.org/en-US/docs/Web/API/${name}`;
	return [
		`### \`${name}\``,
		"",
		...(values ? [fenced(`type ${name} = ${values};`), ""] : []),
		...(text ? [text, ""] : []),
		...(!values && !text.includes("developer.mozilla.org") ? [`[MDN reference](${mdn})`, ""] : []),
	];
};

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const pageContents = PAGES.map((page) => ({
	page,
	lines: [
		...frontmatter(page.title, page.description, page.order),
		`Import from \`${importPath(page.name)}\`, or from the package root, \`${importPath(ROOT)}\`.`,
		"",
		...renderEntries(page.name),
	],
}));
const rootOnlyEntries = renderEntries(ROOT).map((line) =>
	line.startsWith("## ") ? `## Root-only ${line.slice(3).toLowerCase()}` : line,
);
const browserTypes = [...usedDomTypes].sort((a, b) => a.localeCompare(b));

writeFileSync(
	join(outDir, "index.md"),
	await formatCodeBlocks(
		[
			...frontmatter(
				"API overview",
				"Every export of @mmmike/web-push, the entry points it can be imported from, and what it is for.",
				0,
			),
			"Generated from the source's types and JSDoc. Everything can be imported from the package root, `@mmmike/web-push`, or from its entry point, such as `@mmmike/web-push/client`, which carries only that part of the library.",
			"",
			...overviewSections,
			...rootOnlyEntries,
			...(browserTypes.length
				? [
						"## Browser types",
						"",
						"Types the API uses from the browser, as TypeScript's DOM library declares them.",
						"",
						...browserTypes.flatMap(renderDomType),
					]
				: []),
		].join("\n"),
	),
);

for (const { page, lines } of pageContents) {
	writeFileSync(join(outDir, `${page.name}.md`), await formatCodeBlocks(lines.join("\n")));
}

api.close();

if (undocumented.length) {
	console.error(`Exports without JSDoc:\n  ${undocumented.join("\n  ")}`);
	process.exitCode = 1;
}
