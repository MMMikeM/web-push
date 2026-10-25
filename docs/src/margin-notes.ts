import placements from "./margin-notes.json";
import type { Point } from "./components/pen-arrow.ts";

export type Side = "top" | "right" | "bottom" | "left";

/** One end of an arrow: the middle of a side, moved by `offset` px. */
export type End = { side: Side; offset: Point };

/**
 * From a side of the note to a side of its anchor, so the arrow follows the
 * words it points at however they wrap. `bend` bows the curve that many px
 * to the right of its direction, as drawn; negative bows it left.
 */
export type Arrow = { from: End; to: End; bend: number };

/** px from the left or the right edge of the block that holds a note and its anchor. */
type Across = { left: number; right?: never } | { right: number; left?: never };

/** px from the top or the bottom edge of that block. */
type Down = { top: number; bottom?: never } | { bottom: number; top?: never };

/** Positioned beside its anchor, from whichever edges of their block it should follow. */
export type Beside = Across & Down & BesideBox;

type BesideBox = {
	mode: "beside";
	width: number;
	rotate: number;
	/** Space kept below the block, for a note that hangs beneath it. */
	room?: number;
	arrow?: Arrow;
};

/** In the flow straight after its anchor. */
export type Flow = {
	mode: "flow";
	/** px in from the block's left edge, a CSS length, or `auto` to sit against the other side. */
	indent: number | string;
	/** Measures `indent` from the right edge instead, so the note keeps its gap there at any width. */
	side?: "right";
	/** px, or a CSS length such as `min(16rem, 70%)`. */
	width: number | string;
	rotate: number;
	/** Margin above and below, in px, to tuck the note against what's next to it. */
	space: [above: number, below: number];
	/** Shown above its anchor instead, though it still follows it for screen readers. */
	before?: boolean;
	arrow?: Arrow;
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

const besideBox = (placement: Beside) => {
	const across =
		placement.right === undefined ? `left: ${placement.left}px` : `right: ${placement.right}px`;
	const down =
		placement.bottom === undefined ? `top: ${placement.top}px` : `bottom: ${placement.bottom}px`;
	return `position: absolute; inset: auto; ${across}; ${down}; width: ${placement.width}px; margin: 0; order: 0;`;
};

const flowBox = (placement: Flow) => {
	const [above, below] = placement.space;
	const indent = length(placement.indent);
	const [right, left] = placement.side === "right" ? [indent, "auto"] : ["0", indent];
	return `position: relative; inset: auto; width: ${length(placement.width)}; margin: ${above}px ${right} ${below}px ${left}; order: ${placement.before ? -1 : 0};`;
};

const rules = (id: string, at: number, placement: Placement): string => {
	const note = `.margin-note[data-note="${id}"]`;
	const box = placement.mode === "beside" ? besideBox(placement) : flowBox(placement);
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
