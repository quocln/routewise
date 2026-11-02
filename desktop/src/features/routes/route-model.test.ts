import { describe, expect, it } from "vitest";
import { buildListNames } from "@/features/activity/list-names";
import type { RouteEntry } from "@/lib/api/types.gen";
import { filterRoutes, formatAddedAt, isVpnRoute, routeLabel, viaKey, viasOf, vpnTitle } from "./route-model";

const route = (patch: Partial<RouteEntry>): RouteEntry => ({
  ip: "10.0.0.1",
  gateway: "10.8.0.1",
  interface: "utun5",
  domain: "app.corp.example.com",
  addedAt: "2026-10-29T10:15:00Z",
  protected: false,
  ...patch,
});

const sg = route({ ip: "1.1.1.1", clientId: "sg", vpn: "SG", rule: "*.corp.example.com" });
const sg2 = route({ ip: "1.1.1.2", clientId: "sg", vpn: "SG", domain: "b.corp.example.com" });
const stale = route({ ip: "2.2.2.2", clientId: undefined, interface: "utun9", vpn: undefined, domain: "old.example.com" });

describe("vias", () => {
  it("keys a route by client id, then interface", () => {
    expect(viaKey(sg)).toBe("sg");
    expect(viaKey(stale)).toBe("utun9");
    expect(viaKey(route({ clientId: undefined, interface: undefined }))).toBe("");
  });

  it("lists each tunnel once, in first-seen order, with its count", () => {
    expect(viasOf([sg, stale, sg2]).map((v) => [v.id, v.count])).toEqual([["sg", 2], ["utun9", 1]]);
  });
});

describe("filterRoutes", () => {
  const all = [sg, sg2, stale];
  it("returns everything without filters", () => {
    expect(filterRoutes(all, "  ", undefined)).toHaveLength(3);
  });
  it("searches ip, domain, rule, vpn and interface without case", () => {
    expect(filterRoutes(all, "1.1.1.2", undefined)).toEqual([sg2]);
    expect(filterRoutes(all, "OLD.", undefined)).toEqual([stale]);
    expect(filterRoutes(all, "*.corp", undefined)).toEqual([sg]);
    expect(filterRoutes(all, "sg", undefined)).toEqual([sg, sg2]);
    expect(filterRoutes(all, "utun9", undefined)).toEqual([stale]);
  });
  it("restricts to one tunnel and combines with the search", () => {
    expect(filterRoutes(all, "", "sg")).toEqual([sg, sg2]);
    expect(filterRoutes(all, "b.corp", "sg")).toEqual([sg2]);
    expect(filterRoutes(all, "b.corp", "utun9")).toEqual([]);
  });
});

describe("vpnTitle", () => {
  const names = buildListNames(
    { useVpnDns: false, allowIpv6: false, allowedVpnClients: [{ id: "sg", name: "Singapore" }] } as never,
    [],
  );
  it("prefers the current list name, else the recorded one", () => {
    expect(vpnTitle(names, "sg", "SG")).toBe("Singapore");
    expect(vpnTitle(names, "gone", "Old")).toBe("Old");
    expect(vpnTitle(names, "gone", "")).toBeUndefined();
    expect(vpnTitle(names, undefined, undefined)).toBeUndefined();
  });
});

describe("isVpnRoute", () => {
  it("classifies by interface", () => {
    expect(isVpnRoute({ interface: "utun3", gateway: "192.168.1.1" })).toBe(true);
    expect(isVpnRoute({ interface: "en0", gateway: "10.0.0.1" })).toBe(false);
  });
  it("falls back to the gateway when there is no interface", () => {
    expect(isVpnRoute({ interface: "", gateway: "10.8.0.1" })).toBe(true);
    expect(isVpnRoute({ interface: "local", gateway: "8.8.8.8" })).toBe(false);
  });
});

describe("labels", () => {
  it("pluralises routes", () => {
    expect(routeLabel(1)).toBe("1 route");
    expect(routeLabel(0)).toBe("0 routes");
  });
  it("keeps an unparseable timestamp as is", () => {
    expect(formatAddedAt("yesterday")).toBe("yesterday");
    expect(formatAddedAt("2026-10-29T10:15:00Z")).not.toBe("2026-10-29T10:15:00Z");
  });
});
