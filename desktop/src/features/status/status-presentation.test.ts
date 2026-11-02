import { describe, expect, it } from "vitest";
import type { StatusResult } from "@/lib/api/types.gen";
import { RpcError } from "@/lib/rpc/rpc-error";
import { presentStatus } from "./status-presentation";

const base: StatusResult = { running: true, vpnConnected: false, routeCount: 0 };

describe("presentStatus", () => {
  it("reports an unreachable helper", () => {
    const view = presentStatus(undefined, new RpcError({ kind: "unavailable", message: "no socket" }));
    expect(view).toMatchObject({ tone: "error", label: "Helper not running" });
  });

  it("reports a helper error that is not about reachability", () => {
    const view = presentStatus(undefined, new RpcError({ kind: "timeout", seconds: 30 }));
    expect(view.label).toBe("Helper error");
  });

  it("waits for the first answer", () => {
    expect(presentStatus(undefined, null).label).toBe("Connecting");
  });

  it("puts a degraded state first", () => {
    const view = presentStatus({ ...base, degraded: true, degradedReason: "route check failed" }, null);
    expect(view).toMatchObject({ tone: "warning", detail: "route check failed" });
  });

  it("reports no VPN and the ones waiting for approval", () => {
    expect(presentStatus(base, null)).toMatchObject({ tone: "idle", label: "No VPN" });
    const pending = { interface: "utun5", client: { id: "/x", name: "X" } };
    expect(presentStatus({ ...base, pendingVpns: [pending] }, null).detail).toBe("1 VPN waiting for approval");
  });

  it("names the connected tunnels and counts routes", () => {
    const status: StatusResult = {
      ...base,
      vpnConnected: true,
      routeCount: 1,
      tunnels: [{ interface: "utun4", client: { id: "/a", name: "AWS VPN" }, routeCount: 1 }],
    };
    expect(presentStatus(status, null)).toEqual({
      tone: "ok",
      label: "VPN connected",
      detail: "AWS VPN · 1 route",
    });
  });

  it("counts several tunnels", () => {
    const tunnel = (n: number) => ({ interface: `utun${n}`, client: { id: `/${n}`, name: `V${n}` }, routeCount: 2 });
    const view = presentStatus({ ...base, vpnConnected: true, routeCount: 4, tunnels: [tunnel(1), tunnel(2)] }, null);
    expect(view.label).toBe("2 VPNs connected");
    expect(view.detail).toBe("V1, V2 · 4 routes");
  });
});
