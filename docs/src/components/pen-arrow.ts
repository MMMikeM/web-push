export type Point = [x: number, y: number];

/**
 * A pen stroke in a margin note's own coordinates: px from its top left corner,
 * or its bottom left for a note whose height changes with the page width.
 */
export type PenArrow = { from: Point; via: Point; to: Point; corner?: "top" | "bottom" };

const HEAD_LENGTH = 9;
const HEAD_SPREAD = (32 * Math.PI) / 180;

const round = (value: number) => Math.round(value * 10) / 10;

/** The SVG path of a curve from `from` to `to`, bent towards `via`, with an open head at `to`. */
export const penArrowPath = ({ from, via, to }: PenArrow): string => {
	const back = Math.atan2(via[1] - to[1], via[0] - to[0]);
	const barb = (side: number): string =>
		`${round(to[0] + HEAD_LENGTH * Math.cos(back + side * HEAD_SPREAD))} ${round(to[1] + HEAD_LENGTH * Math.sin(back + side * HEAD_SPREAD))}`;
	return `M${from.join(" ")}Q${via.join(" ")} ${to.join(" ")}M${barb(1)}L${to.join(" ")}L${barb(-1)}`;
};
