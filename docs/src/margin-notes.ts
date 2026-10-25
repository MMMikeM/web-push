import placements from "./margin-notes.json";
import type { PenArrow } from "./components/pen-arrow.ts";

/** Positioned beside its anchor: px from the top left of the block that holds both. */
export type Beside = {
	mode: "beside";
	left: number;
	top: number;
	width: number;
	rotate: number;
	/** Space kept below the block, for a note that hangs beneath it. */
	room?: number;
	arrow?: PenArrow;
};

/** In the flow straight after its anchor. */
export type Flow = {
	mode: "flow";
	/** px in from the start of the block, a CSS length, or `auto` to sit at its end. */
	indent: number | string;
	/** px, or a CSS length such as `min(16rem, 70%)`. */
	width: number | string;
	rotate: number;
	/** Margin above and below, in px, to tuck the note against what's next to it. */
	space: [above: number, below: number];
	/** Shown above its anchor instead, though it still follows it for screen readers. */
	before?: boolean;
	arrow?: PenArrow;
};

export type Placement = Beside | Flow;

/** A note's placements, keyed by the viewport width in px from which each applies. */
export type NotePlacements = Record<string, Placement>;

// A JSON import types "beside" as any string and [above, below] as any array.
export const notePlacements = placements as unknown as Record<string, NotePlacements>;

const length = (value: number | string) => (typeof value === "number" ? `${value}px` : value);

/** The ranges of viewport widths the placements cover, from narrowest. */
export const ranges = (note: NotePlacements) => {
	const starts = Object.keys(note)
		.map(Number)
		.toSorted((a, b) => a - b);
	return starts.map((from, index) => ({ from, to: starts[index + 1], placement: note[from] }));
};

const media = (from: number, to: number | undefined) =>
	[from > 0 && `(min-width: ${from}px)`, to !== undefined && `(max-width: ${to - 0.02}px)`]
		.filter(Boolean)
		.join(" and ") || "all";

const rules = (id: string, at: number, placement: Placement): string => {
	const note = `.margin-note[data-note="${id}"]`;
	const box =
		placement.mode === "beside"
			? `position: absolute; left: ${placement.left}px; top: ${placement.top}px; width: ${placement.width}px; margin: 0; order: 0; font-size: 1.0625rem;`
			: `position: relative; left: auto; top: auto; width: ${length(placement.width)}; margin: ${placement.space[0]}px 0 ${placement.space[1]}px ${length(placement.indent)}; order: ${placement.before ? -1 : 0}; font-size: 1rem;`;
	const room =
		placement.mode === "beside" && placement.room
			? ` :has(> ${note}) { padding-bottom: ${placement.room}px; }`
			: "";
	return `${note} { ${box} } ${note} .text { rotate: ${placement.rotate}deg; } ${note} .arrow[data-at="${at}"] { display: block; }${room}`;
};

/** The stylesheet that places one note at each of its widths. */
export const placementCss = (id: string, note: NotePlacements): string =>
	ranges(note)
		.map(({ from, to, placement }) => `@media ${media(from, to)} { ${rules(id, from, placement)} }`)
		.join("\n");
