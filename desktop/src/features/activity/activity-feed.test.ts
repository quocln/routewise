import { describe, expect, it } from "vitest";
import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import { MAX_KEPT_EVENTS, appendOlder, mergeAccess, mergeActivity } from "./activity-feed";

const event = (seq: number): ActivityEvent => ({ seq, time: "2026-10-29T00:00:00Z", kind: "dns", name: `h${seq}` });
const result = (...seqs: number[]) => ({ latest: Math.max(...seqs), events: seqs.map(event) });

describe("mergeActivity", () => {
  it("shows the first result newest first", () => {
    expect(mergeActivity([], result(1, 2, 3), true).map((e) => e.seq)).toEqual([3, 2, 1]);
  });

  it("puts later events in front and skips ones already shown", () => {
    const shown = mergeActivity([], result(1, 2), true);
    expect(mergeActivity(shown, result(2, 3, 4), false).map((e) => e.seq)).toEqual([4, 3, 2, 1]);
  });

  it("keeps the same list when nothing is new", () => {
    const shown = mergeActivity([], result(1), true);
    expect(mergeActivity(shown, { latest: 1, events: [] }, false)).toBe(shown);
  });

  it("replaces what is shown after a restart", () => {
    const shown = mergeActivity([], result(10, 11), true);
    expect(mergeActivity(shown, result(1), true).map((e) => e.seq)).toEqual([1]);
  });

  it("caps the list", () => {
    const many = Array.from({ length: MAX_KEPT_EVENTS + 50 }, (_, i) => i + 1);
    expect(mergeActivity([], result(...many), true)).toHaveLength(MAX_KEPT_EVENTS);
  });
});

describe("mergeActivity floor", () => {
  it("keeps cleared events hidden when the stream starts over", () => {
    expect(mergeActivity([], result(1, 2, 3, 4), true, 3).map((e) => e.seq)).toEqual([4]);
  });
});

describe("access feed", () => {
  const entry = (id: number) => ({
    id,
    time: "2026-10-29T00:00:00Z",
    ip: "10.0.0.1",
    port: 443,
    proto: "tcp",
    interface: "en0",
    verdict: "direct",
  });
  const page = (...ids: number[]) => ({ latestId: Math.max(...ids), entries: ids.map(entry) });

  it("replaces on the first result and prepends later ones, newest first", () => {
    const shown = mergeAccess([], page(1, 2, 3), true);
    expect(shown.map((e) => e.id)).toEqual([3, 2, 1]);
    expect(mergeAccess(shown, page(4, 5), false).map((e) => e.id)).toEqual([5, 4, 3, 2, 1]);
    expect(mergeAccess(shown, { latestId: 3, entries: [] }, false)).toBe(shown);
  });

  it("appends only rows older than the oldest shown", () => {
    const shown = mergeAccess([], page(10, 11), true);
    expect(appendOlder(shown, [entry(11), entry(10), entry(9), entry(8)]).map((e) => e.id)).toEqual([11, 10, 9, 8]);
  });
});
