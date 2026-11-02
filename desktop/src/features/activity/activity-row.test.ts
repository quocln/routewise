import { beforeAll, describe, expect, it } from "vitest";
import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import type { Entry } from "@/lib/api/history.gen";
import { DEFAULT_FILTERS, applyFilters } from "./activity-filters";
import { formatTime, rowFromEntry, rowFromEvent } from "./activity-row";
import { ListNames } from "./list-names";

const STAMP = "2026-10-28T09:30:15Z";
const NOW = new Date("2026-10-28T10:00:00Z");
const names = new ListNames([]);

beforeAll(() => {
  process.env.TZ = "UTC";
});

const entry = (over: Partial<Entry>): Entry => ({
  id: 9,
  time: STAMP,
  name: "jira.corp.com",
  ip: "10.1.2.3",
  port: 443,
  proto: "tcp",
  interface: "utun4",
  vpn: "SG",
  verdict: "vpn",
  ...over,
});

describe("connection rows", () => {
  it("lays a connection out as in the preview", () => {
    const row = rowFromEntry(entry({ list: "routewise-wireguard:sg", rule: "*.corp.com" }), names, NOW);
    expect(row).toMatchObject({
      title: "jira.corp.com",
      endpoint: "10.1.2.3:443",
      proto: "TCP",
      rule: "*.corp.com",
      route: { kind: "vpn", client: "SG" },
      time: "09:30:15",
    });
    expect(row.warning).toBeUndefined();
  });

  it("brackets an IPv6 endpoint and falls back to the address as title", () => {
    const row = rowFromEntry(entry({ name: undefined, ip: "2606:4700::1" }), names, NOW);
    expect(row.title).toBe("2606:4700::1");
    expect(row.endpoint).toBe("[2606:4700::1]:443");
  });

  it("warns with the VPN's name when a listed connection went direct", () => {
    const row = rowFromEntry(
      entry({ verdict: "direct", vpn: undefined, interface: "en0", list: "routewise-wireguard:sg", rule: "wiki.sg.io" }),
      names,
      NOW,
    );
    expect(row.warning).toBe("In sg's list, but sg was not connected, so it went direct.");
    expect(row.warningLabel).toBe("sg off");
    expect(row.route).toEqual({ kind: "direct" });
  });

  it("words the Any VPN mismatch and names an unknown verdict Other", () => {
    const row = rowFromEntry(entry({ verdict: "other", list: "" }), names, NOW);
    expect(row.warningLabel).toBe("no VPN");
    expect(row.warning).toBe("In the Any VPN list, but no VPN app was connected, so it went direct.");
    expect(row.route).toEqual({ kind: "other" });
  });

  it("puts the date before the time of an earlier day", () => {
    expect(formatTime(new Date("2026-10-27T23:05:09Z"), NOW)).toBe("Oct 27 23:05:09");
    expect(formatTime(new Date("2026-10-28T01:05:09Z"), NOW)).toBe("01:05:09");
  });
});

const ev = (over: Partial<ActivityEvent>): ActivityEvent => ({ seq: 1, time: STAMP, kind: "dns", ...over });

describe("event rows", () => {
  it("warns when a listed DNS name went direct, and not when it was routed", () => {
    const missed = rowFromEvent(
      ev({ name: "wiki.sg.io", list: "routewise-wireguard:sg", addresses: [{ ip: "10.0.0.0", verdict: "direct" }] }),
      names,
      NOW,
    );
    expect(missed.warning).toBeDefined();
    expect(missed.route).toEqual({ kind: "direct" });

    const routed = rowFromEvent(
      ev({ name: "jira.corp.com", list: "routewise-wireguard:sg", vpn: "SG", addresses: [{ ip: "10.0.0.0", verdict: "vpn" }] }),
      names,
      NOW,
    );
    expect(routed.warning).toBeUndefined();
    expect(routed.route).toEqual({ kind: "vpn", client: "SG" });
    expect(routed.endpoint).toBe("10.0.0.0");
  });

  it("treats a listed name's IPv6 answer as a notice, not a VPN that was off", () => {
    const aaaa = ev({
      seq: 7,
      name: "wiki.sg.io",
      list: "routewise-wireguard:sg",
      rule: "wiki.sg.io",
      addresses: [
        { ip: "2606:4700::1", verdict: "direct" },
        { ip: "2606:4700::2", verdict: "direct" },
      ],
    });
    const row = rowFromEvent(aaaa, names, NOW);
    expect(row.warning).toBeUndefined();
    expect(row.route).toBeUndefined();
    expect(row.noticeLabel).toBe("IPv6 not routed");
    expect(row.notice).toBe(
      "RouteWise routes IPv4 only, so this IPv6 answer does not go through sg. On a network with IPv6, apps that use it go direct.",
    );
    expect(applyFilters([aaaa], "dns", { ...DEFAULT_FILTERS, range: "last7Days", via: { kind: "direct" } }, NOW)).toEqual([]);
  });

  it("says IPv6 is blocked when every address is", () => {
    const row = rowFromEvent(
      ev({
        seq: 9,
        name: "wiki.sg.io",
        list: "routewise-wireguard:sg",
        addresses: [{ ip: "2606:4700::1", verdict: "direct", blocked: true }],
      }),
      names,
      NOW,
    );
    expect(row.noticeLabel).toBe("IPv6 blocked");
    expect(row.notice).toBe(
      "RouteWise blocks the IPv6 addresses of listed domains, so apps connect over IPv4, which goes through the VPN. Settings › IPv6 turns this off.",
    );
    expect(row.warning).toBeUndefined();
    expect(row.route).toBeUndefined();
  });

  it("routes an unlisted IPv6 answer direct without a notice", () => {
    const row = rowFromEvent(
      ev({ seq: 8, name: "example.com", addresses: [{ ip: "2606:2800::1", verdict: "direct" }] }),
      names,
      NOW,
    );
    expect(row.route).toEqual({ kind: "direct" });
    expect(row.notice).toBeUndefined();
  });

  it("gives routing events the same layout without inventing a route", () => {
    const removed = rowFromEvent(
      ev({ kind: "route_removed", name: "a.com", vpn: "SG", addresses: [{ ip: "10.0.0.0", verdict: "direct" }] }),
      names,
      NOW,
    );
    expect(removed.route).toBeUndefined();
    expect(removed.warning).toBeUndefined();

    const connected = rowFromEvent(ev({ seq: 2, kind: "vpn", name: "SG", detail: "connected" }), names, NOW);
    expect(connected).toMatchObject({ title: "SG", detail: "connected", route: { kind: "vpn", client: "SG" } });

    const many = rowFromEvent(
      ev({ seq: 3, name: "big.com", addresses: [0, 1, 2, 3].map((i) => ({ ip: `10.0.0.${i}`, verdict: "direct" })) }),
      names,
      NOW,
    );
    expect(many.endpoint).toBe("10.0.0.0, 10.0.0.1 +2");
  });
});
