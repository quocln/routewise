import { describe, expect, it } from "vitest";
import { EMPTY_SELECTION, selectionAfterClick } from "./entry-selection";

const rows = ["a", "b", "c", "d"];
const plain = { toggle: false, range: false };

describe("selectionAfterClick", () => {
  it("selects just the clicked entry", () => {
    const first = selectionAfterClick(EMPTY_SELECTION, rows, "b", plain);
    expect([...first.selected]).toEqual(["b"]);
    expect([...selectionAfterClick(first, rows, "c", plain).selected]).toEqual(["c"]);
  });

  it("toggles an entry in and out", () => {
    const one = selectionAfterClick(EMPTY_SELECTION, rows, "a", plain);
    const two = selectionAfterClick(one, rows, "c", { toggle: true, range: false });
    expect([...two.selected].sort()).toEqual(["a", "c"]);
    expect([...selectionAfterClick(two, rows, "a", { toggle: true, range: false }).selected]).toEqual(["c"]);
  });

  it("selects the range from the anchor in either direction", () => {
    const anchor = selectionAfterClick(EMPTY_SELECTION, rows, "b", plain);
    expect([...selectionAfterClick(anchor, rows, "d", { toggle: false, range: true }).selected]).toEqual(["b", "c", "d"]);
    expect([...selectionAfterClick(anchor, rows, "a", { toggle: false, range: true }).selected]).toEqual(["a", "b"]);
  });
});
