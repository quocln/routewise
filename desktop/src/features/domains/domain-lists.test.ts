import { describe, expect, it } from "vitest";
import type { ProfileInfo, StatusResult, TunnelStatus, VPNClient } from "@/lib/api/types.gen";
import {
  activeVpnName,
  buildListItems,
  countListIds,
  isBuiltInClientId,
  isVpnConnected,
  listCaption,
  profileClientId,
  profileIdFromClientId,
} from "./domain-lists";

const app: VPNClient = { id: "/Applications/AWS VPN Client/aws", name: "AWS VPN Client" };
const builtIn: VPNClient = { id: "routewise-wireguard:ab12cd34", name: "Office" };

function tunnel(client: VPNClient, iface: string): TunnelStatus {
  return { interface: iface, client, routeCount: 1 };
}

function status(tunnels: TunnelStatus[], vpnConnected = true): StatusResult {
  return { running: true, vpnConnected, routeCount: 1, tunnels };
}

function profile(state: string): ProfileInfo {
  return { id: "ab12cd34", kind: "wireguard", name: "Office", autoConnect: false, dns: [], state };
}

describe("built-in client ids", () => {
  it("tells profiles from apps", () => {
    expect(isBuiltInClientId("routewise-wireguard:ab12cd34")).toBe(true);
    expect(isBuiltInClientId("routewise-outline:ff00")).toBe(true);
    expect(isBuiltInClientId("/Applications/AWS VPN Client/aws")).toBe(false);
    expect(isBuiltInClientId("")).toBe(false);
    expect(profileIdFromClientId("routewise-outline:ff00")).toBe("ff00");
    expect(profileIdFromClientId("routewise-outline:")).toBeUndefined();
    expect(profileClientId({ kind: "outline", id: "ff00" })).toBe("routewise-outline:ff00");
  });
});

describe("connection state", () => {
  it("Any VPN is not connected through a built-in tunnel alone", () => {
    expect(isVpnConnected("", status([tunnel(builtIn, "utun9")]))).toBe(false);
    const both = status([tunnel(builtIn, "utun9"), tunnel(app, "utun4")]);
    expect(isVpnConnected("", both)).toBe(true);
    expect(activeVpnName(both)).toBe("AWS VPN Client");
  });

  it("falls back to vpnClient for a helper that reports no tunnels", () => {
    const legacy: StatusResult = { ...status([]), vpnClient: app };
    expect(isVpnConnected(app.id, legacy)).toBe(true);
    expect(isVpnConnected("/other", legacy)).toBe(false);
    expect(isVpnConnected(app.id, undefined)).toBe(false);
  });
});

describe("buildListItems", () => {
  it("groups lists and takes a built-in state from its profile", () => {
    const items = buildListItems([app, builtIn], [profile("connecting")], status([tunnel(builtIn, "utun9")]));
    expect(items.map((i) => i.id)).toEqual(["", builtIn.id, app.id]);
    expect(items.map((i) => i.group)).toEqual(["any", "builtIn", "app"]);
    expect(items[1].stateLabel).toBe("Connecting");
    expect(items[1].isRouting).toBe(false);
    expect(items[0].isRouting).toBe(false);
    expect(items[2].isRouting).toBe(false);
  });

  it("always has Any VPN, and names a built-in list after its profile", () => {
    expect(buildListItems([], [], undefined).map((i) => i.id)).toEqual([""]);
    const items = buildListItems([builtIn], [{ ...profile("connected"), name: "Work" }], undefined);
    expect(items[1].title).toBe("Work");
    expect(items[1].isRouting).toBe(true);
  });

  it("shows no state for a built-in client without a profile", () => {
    const items = buildListItems([builtIn], [], undefined);
    expect(items[1].stateLabel).toBe("");
    expect(items[1].title).toBe("Office");
  });

  it("counts profiles whose client is not allowed yet", () => {
    const items = buildListItems([app], [profile("connected")], undefined);
    expect(countListIds(items, [profile("connected")])).toEqual(["", app.id, builtIn.id].sort());
  });
});

describe("captions", () => {
  it("explains each list", () => {
    const up = status([tunnel(app, "utun4")]);
    const items = buildListItems([app, builtIn], [profile("connected")], up);
    expect(listCaption(items[0], up)).toBe(
      "Routes through the highest-priority connected VPN (AWS VPN Client right now). Built-in VPNs never carry this list.",
    );
    expect(listCaption(items[1], up)).toBe("Connected — these entries route through Office.");
    expect(listCaption(items[2], up)).toBe("Connected — these domains route through this VPN");
    const down = buildListItems([app, builtIn], [profile("disconnected")], undefined);
    expect(listCaption(down[1], undefined)).toBe(
      "Not routing — these entries go direct until Office is connected and working.",
    );
    expect(listCaption(down[2], undefined)).toBe("Not connected — these domains go direct until it connects");
  });
});
