import { beforeAll, describe, expect, it } from "vitest";
import type { Address, Event as ActivityEvent } from "@/lib/api/activity.gen";
import { applyFilters, accessParams, DEFAULT_FILTERS, sinceMs, viaOptions, type ActivityFilters } from "./activity-filters";

const STAMP = "2026-10-28T09:30:15Z";
const NOW = new Date("2026-10-28T10:00:00Z");

beforeAll(() => {
  // Ranges are local-day based; the fixtures are written in UTC.
  process.env.TZ = "UTC";
});

function event(
  seq: number,
  kind: string,
  o: { name?: string; verdicts?: string[]; detail?: string; list?: string; rule?: string; vpn?: string; time?: string } = {},
): ActivityEvent {
  const addresses: Address[] = (o.verdicts ?? []).map((verdict, i) => ({ ip: `10.0.0.${i}`, verdict }));
  return { seq, time: o.time ?? STAMP, kind, addresses, name: o.name, detail: o.detail, list: o.list, rule: o.rule, vpn: o.vpn };
}

const filters = (over: Partial<ActivityFilters> = {}): ActivityFilters => ({ ...DEFAULT_FILTERS, range: "last7Days", ...over });
const seqs = (events: ActivityEvent[], mode: Parameters<typeof applyFilters>[1], f: ActivityFilters) =>
  applyFilters(events, mode, f, NOW).map((e) => e.seq);

describe("activity filters", () => {
  it("starts on today", () => {
    expect(DEFAULT_FILTERS.range).toBe("today");
    expect(new Date(sinceMs("today", NOW)).toISOString()).toBe("2026-10-28T00:00:00.000Z");
  });

  it("lists each mode's kinds", () => {
    const all = ["dns", "vpn", "route_added", "route_removed", "refused", "mystery"].map((k, i) =>
      event(i + 1, k, { verdicts: ["direct"] }),
    );
    expect(seqs(all, "dns", filters())).toEqual([1]);
    expect(seqs(all, "events", filters())).toEqual([2, 3, 4, 5]);
    expect(seqs(all, "connections", filters())).toEqual([]);
  });

  it("keeps only events of the chosen list, and Any VPN is a list of its own", () => {
    const all = [event(1, "dns", { name: "a", list: "wg" }), event(2, "dns", { name: "b", list: "" }), event(3, "dns", { name: "c" })];
    expect(seqs(all, "dns", filters({ list: null }))).toEqual([1, 2, 3]);
    expect(seqs(all, "dns", filters({ list: "wg" }))).toEqual([1]);
    expect(seqs(all, "dns", filters({ list: "" }))).toEqual([2]);
  });

  it("filters by VPN, direct, and never other", () => {
    const all = [
      event(1, "dns", { verdicts: ["vpn"], vpn: "SG" }),
      event(2, "dns", { verdicts: ["vpn"], vpn: "AWS" }),
      event(3, "dns", { verdicts: ["direct"] }),
      event(4, "vpn", { name: "SG", detail: "connected" }),
      event(5, "dns"),
    ];
    expect(seqs(all, "dns", filters())).toEqual([1, 2, 3, 5]);
    expect(seqs(all, "dns", filters({ via: { kind: "vpn", name: "SG" } }))).toEqual([1]);
    expect(seqs(all, "events", filters({ via: { kind: "vpn", name: "SG" } }))).toEqual([4]);
    expect(seqs(all, "dns", filters({ via: { kind: "direct" } }))).toEqual([3]);
    expect(seqs(all, "dns", filters({ via: { kind: "other" } }))).toEqual([]);
  });

  it("does not count an unrouted IPv6 answer as a listed name that went direct", () => {
    const aaaa: ActivityEvent = {
      seq: 1,
      time: STAMP,
      kind: "dns",
      name: "wiki.sg.io",
      list: "wg",
      addresses: [{ ip: "2606:4700::1", verdict: "direct" }],
    };
    const unlisted: ActivityEvent = { ...aaaa, seq: 2, list: undefined };
    expect(seqs([aaaa, unlisted], "dns", filters({ via: { kind: "direct" } }))).toEqual([2]);
  });

  it("drops events before the range start", () => {
    const all = [
      event(1, "dns", { time: "2026-10-28T09:30:00Z" }),
      event(2, "dns", { time: "2026-10-28T00:30:00Z" }),
      event(3, "dns", { time: "2026-10-27T12:00:00Z" }),
    ];
    expect(seqs(all, "dns", filters({ range: "lastHour" }))).toEqual([1]);
    expect(seqs(all, "dns", filters({ range: "today" }))).toEqual([1, 2]);
    expect(seqs(all, "dns", filters({ range: "last24Hours" }))).toEqual([1, 2, 3]);
  });

  it("searches name, IP, detail, rule, and VPN without regard to case", () => {
    const all = [
      event(1, "route_added", { name: "Git.Corp.test" }),
      event(2, "dns", { verdicts: ["vpn"] }),
      event(3, "refused", { detail: "not in tunnel subnet" }),
      event(4, "dns", { name: "x", rule: "*.internal.example" }),
      event(5, "route_added", { name: "y", vpn: "Office Tunnel" }),
    ];
    const search = (s: string, mode: "dns" | "events") => seqs(all, mode, filters({ search: s }));
    expect(search("git.corp", "events")).toEqual([1]);
    expect(search("10.0.0.0", "dns")).toEqual([2]);
    expect(search("SUBNET", "events")).toEqual([3]);
    expect(search("internal", "dns")).toEqual([4]);
    expect(search("office", "events")).toEqual([5]);
    expect(search("nothing", "dns")).toEqual([]);
    expect(search("subnet", "dns")).toEqual([]);
    expect(search("   ", "dns")).toEqual([2, 4]);
  });
});

describe("access params", () => {
  it("carries the range and every filter the helper applies", () => {
    const params = accessParams(
      { range: "today", via: { kind: "vpn", name: "SG" }, list: "", search: "  jira " },
      500,
      NOW,
    );
    expect(params).toEqual({ sinceMs: sinceMs("today", NOW), limit: 500, vpn: "SG", list: "", search: "jira" });
  });

  it("sends the verdict of Direct and Other, and nothing for All", () => {
    expect(accessParams({ ...DEFAULT_FILTERS, via: { kind: "direct" } }, 5, NOW).verdict).toBe("direct");
    expect(accessParams({ ...DEFAULT_FILTERS, via: { kind: "other" } }, 5, NOW).verdict).toBe("other");
    const all = accessParams(DEFAULT_FILTERS, 5, NOW);
    expect(all).not.toHaveProperty("verdict");
    expect(all).not.toHaveProperty("list");
    expect(all).not.toHaveProperty("search");
  });
});

describe("viaOptions", () => {
  it("lists All, Direct, the known VPNs sorted, the selected one, then Other", () => {
    const options = viaOptions(["b-vpn", "A-vpn"], ["b-vpn", ""], { kind: "vpn", name: "gone" });
    expect(options.map((o) => (o.kind === "vpn" ? o.name : o.kind))).toEqual([
      "all",
      "direct",
      "A-vpn",
      "b-vpn",
      "gone",
      "other",
    ]);
  });
});
