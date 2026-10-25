export type Point = [x: number, y: number];

/** A pen stroke from `from` to `to`, bowed towards `via`. */
export type PenArrow = { from: Point; via: Point; to: Point };

const HEAD_LENGTH = 9;
const HEAD_SPREAD = (32 * Math.PI) / 180;

const round = (value: number) => Math.round(value * 10) / 10;

/** The SVG paths of a curve from `from` to `to`, bent towards `via`, and its open head at `to`. */
export const penArrowParts = ({ from, via, to }: PenArrow): { curve: string; head: string } => {
	const back = Math.atan2(via[1] - to[1], via[0] - to[0]);
	const barb = (side: number): string =>
		`${round(to[0] + HEAD_LENGTH * Math.cos(back + side * HEAD_SPREAD))} ${round(to[1] + HEAD_LENGTH * Math.sin(back + side * HEAD_SPREAD))}`;
	return {
		curve: `M${from.join(" ")}Q${via.join(" ")} ${to.join(" ")}`,
		head: `M${barb(1)}L${to.join(" ")}L${barb(-1)}`,
	};
};
