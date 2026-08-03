// SVG path builders for the node shapes used to encode health (shape is a colour-independent cue).

import type { NodeShape } from "./encodings";

export function shapePath(shape: NodeShape, x: number, y: number, w: number, h: number): string {
  switch (shape) {
    case "hexagon":
      return hexagon(x, y, w, h);
    case "octagon":
      return octagon(x, y, w, h);
    case "roundedRect":
    default:
      return roundedRect(x, y, w, h, 10);
  }
}

function roundedRect(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, w / 2, h / 2);
  return [
    `M ${x + rr} ${y}`,
    `H ${x + w - rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + w} ${y + rr}`,
    `V ${y + h - rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + w - rr} ${y + h}`,
    `H ${x + rr}`,
    `A ${rr} ${rr} 0 0 1 ${x} ${y + h - rr}`,
    `V ${y + rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + rr} ${y}`,
    "Z",
  ].join(" ");
}

function hexagon(x: number, y: number, w: number, h: number): string {
  const c = Math.min(w * 0.16, h / 2);
  return [
    `M ${x + c} ${y}`,
    `H ${x + w - c}`,
    `L ${x + w} ${y + h / 2}`,
    `L ${x + w - c} ${y + h}`,
    `H ${x + c}`,
    `L ${x} ${y + h / 2}`,
    "Z",
  ].join(" ");
}

function octagon(x: number, y: number, w: number, h: number): string {
  const cx = Math.min(w * 0.28, w / 3);
  const cy = Math.min(h * 0.28, h / 3);
  return [
    `M ${x + cx} ${y}`,
    `H ${x + w - cx}`,
    `L ${x + w} ${y + cy}`,
    `V ${y + h - cy}`,
    `L ${x + w - cx} ${y + h}`,
    `H ${x + cx}`,
    `L ${x} ${y + h - cy}`,
    `V ${y + cy}`,
    "Z",
  ].join(" ");
}
