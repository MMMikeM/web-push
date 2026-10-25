import type { Arrow, End, Side } from "../margin-notes.ts";
import { penArrowParts, type Point } from "./pen-arrow.ts";

type Box = Pick<DOMRect, "left" | "right" | "top" | "bottom">;

const round = (value: number) => Math.round(value * 10) / 10;

/**
 * What an arrow can point at in an anchor, in reading order: a paragraph's
 * lines of text, an inline element's lines, or a box.
 */
export const anchorBoxes = (anchor: Element): Box[] => {
	if (anchor instanceof HTMLParagraphElement) {
		const range = document.createRange();
		range.selectNodeContents(anchor);
		return [...range.getClientRects()].filter((line) => line.width > 0);
	}
	const lines = [...anchor.getClientRects()];
	return lines.length > 0 ? lines : [anchor.getBoundingClientRect()];
};

/** The middle of a side: of the first line for top and left, the last for right and bottom. */
export const sidePoint = (side: Side, boxes: Box[]): Point => {
	const first = boxes[0];
	const last = boxes.at(-1) ?? first;
	switch (side) {
		case "top":
			return [(first.left + first.right) / 2, first.top];
		case "left":
			return [first.left, (first.top + first.bottom) / 2];
		case "right":
			return [last.right, (last.top + last.bottom) / 2];
		case "bottom":
			return [(last.left + last.right) / 2, last.bottom];
	}
};

export const endPoint = (end: End, boxes: Box[]): Point => {
	const [x, y] = sidePoint(end.side, boxes);
	return [x + end.offset[0], y + end.offset[1]];
};

/** The point the curve bows towards: `bend` px off the middle of the line between its ends. */
export const bendPoint = (from: Point, to: Point, bend: number): Point => {
	const [dx, dy] = [to[0] - from[0], to[1] - from[1]];
	const length = Math.hypot(dx, dy) || 1;
	return [
		(from[0] + to[0]) / 2 - (dy / length) * bend,
		(from[1] + to[1]) / 2 + (dx / length) * bend,
	];
};

/** Where an arrow's ends and bend fall, in viewport coordinates. */
export const arrowPoints = (note: Element, anchor: Element, arrow: Arrow) => {
	const from = endPoint(arrow.from, [note.getBoundingClientRect()]);
	const to = endPoint(arrow.to, anchorBoxes(anchor));
	return { from, via: bendPoint(from, to, arrow.bend), to };
};

/** Draws every margin note arrow on show from where its note and its anchor sit now. */
export const drawNoteArrows = () => {
	for (const note of document.querySelectorAll<HTMLElement>(".margin-note[data-anchor]")) {
		const anchor = document.querySelector(note.dataset.anchor ?? "");
		for (const svg of note.querySelectorAll<SVGSVGElement>("svg.arrow[data-arrow]")) {
			if (!anchor || getComputedStyle(svg).display === "none") {
				continue;
			}
			const origin = svg.getBoundingClientRect();
			const local = ([x, y]: Point): Point => [round(x - origin.left), round(y - origin.top)];
			const { from, via, to } = arrowPoints(note, anchor, JSON.parse(svg.dataset.arrow ?? ""));
			const { curve, head } = penArrowParts({ from: local(from), via: local(via), to: local(to) });
			svg.querySelector(".curve")?.setAttribute("d", curve);
			svg.querySelector(".head")?.setAttribute("d", head);
		}
	}
};

/**
 * Keeps the arrows on their anchors as fonts load and the page reflows: a
 * different width, a different text size or a different browser all move
 * the words an arrow points at.
 */
export const followNoteArrows = () => {
	let queued = 0;
	const redraw = () => {
		cancelAnimationFrame(queued);
		queued = requestAnimationFrame(drawNoteArrows);
	};
	redraw();
	void document.fonts?.ready.then(redraw);
	new ResizeObserver(redraw).observe(document.documentElement);
	addEventListener("resize", redraw);
	addEventListener("note-arrows:redraw", redraw);
};
