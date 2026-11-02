import { describe, expect, it } from "vitest";
import { findMatches, nextMatch, previousMatch } from "./find-matches";

describe("find", () => {
  it("finds case-insensitive, non-overlapping matches", () => {
    expect(findMatches("a.com\nA.com\naaa", "a.com")).toEqual([0, 6]);
    expect(findMatches("aaaa", "aa")).toEqual([0, 2]);
    expect(findMatches("abc", "")).toEqual([]);
  });

  it("steps forward and back, wrapping around", () => {
    const matches = [0, 10, 20];
    expect(nextMatch(matches, 0)).toBe(0);
    expect(nextMatch(matches, 5)).toBe(10);
    expect(nextMatch(matches, 21)).toBe(0);
    expect(previousMatch(matches, 15)).toBe(10);
    expect(previousMatch(matches, 0)).toBe(20);
    expect(nextMatch([], 3)).toBeUndefined();
    expect(previousMatch([], 3)).toBeUndefined();
  });
});
