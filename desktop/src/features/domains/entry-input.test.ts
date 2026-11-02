import { describe, expect, it } from "vitest";
import { firstInvalidEntry, parseDomainLines, parseEntryInput, planAdd } from "./entry-input";

describe("parseEntryInput", () => {
  it("splits on commas, spaces, semicolons and new lines", () => {
    expect(parseEntryInput(" a.example.com, b.example.com\n10.0.0.0/16;  *.c.example.com ")).toEqual([
      "a.example.com",
      "b.example.com",
      "10.0.0.0/16",
      "*.c.example.com",
    ]);
    expect(parseEntryInput(" ,\n ")).toEqual([]);
  });
});

describe("parseDomainLines", () => {
  it("keeps one trimmed entry per line and drops blanks and comments", () => {
    expect(parseDomainLines("a.com\r\n  b.com  \n\n# note\nc.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("reports the first malformed line with its reason", () => {
    expect(firstInvalidEntry(["a.com", "ex*ample", "10.0.0.0/7"])).toBe("ex*ample: Invalid pattern format");
    expect(firstInvalidEntry(["a.com"])).toBeUndefined();
  });
});

describe("planAdd", () => {
  it("adds fresh entries and counts the skipped ones", () => {
    expect(planAdd("b.com c.com a.com", ["a.com", "z.com"])).toEqual({ kind: "add", fresh: ["b.com", "c.com"], skipped: 1 });
  });

  it("does nothing for blank input", () => {
    expect(planAdd(" , ", [])).toEqual({ kind: "nothing" });
  });

  it("adds nothing when any entry is malformed", () => {
    expect(planAdd("a.com ex*ample", [])).toEqual({ kind: "invalid", message: "ex*ample: Invalid pattern format" });
  });

  it("detects duplicates by canonical form, including within the input", () => {
    expect(planAdd("10.20.5.1/16", ["10.20.0.0/16"])).toEqual({ kind: "duplicates" });
    expect(planAdd("10.20.30.40/32", ["10.20.30.40"])).toEqual({ kind: "duplicates" });
    expect(planAdd("10.21.0.0/16 10.21.1.1/16", [])).toEqual({ kind: "add", fresh: ["10.21.0.0/16"], skipped: 1 });
  });
});
