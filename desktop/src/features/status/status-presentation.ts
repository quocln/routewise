import type { RpcError } from "@/lib/rpc/rpc-error";
import type { StatusResult } from "@/lib/api/types.gen";

export type StatusTone = "ok" | "idle" | "warning" | "error";

export interface StatusView {
  tone: StatusTone;
  label: string;
  detail: string;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/** What the status header says for the helper's state, or for failing to read it. */
export function presentStatus(status: StatusResult | undefined, error: RpcError | null): StatusView {
  if (error) {
    return error.isUnavailable
      ? { tone: "error", label: "Helper not running", detail: error.message }
      : { tone: "error", label: "Helper error", detail: error.message };
  }
  if (!status) return { tone: "idle", label: "Connecting", detail: "Reaching the helper" };
  if (status.degraded) {
    return {
      tone: "warning",
      label: "Needs attention",
      detail: status.degradedReason ?? "Route compensation could not be verified",
    };
  }
  if (!status.running) return { tone: "error", label: "Helper stopped", detail: "The routing helper is not running" };

  const tunnels = status.tunnels ?? [];
  if (!status.vpnConnected) {
    const pending = status.pendingVpns?.length ?? 0;
    return {
      tone: "idle",
      label: "No VPN",
      detail: pending > 0 ? `${plural(pending, "VPN")} waiting for approval` : "Waiting for a VPN to connect",
    };
  }
  const names = tunnels.map((t) => t.client.name || t.interface);
  const where = names.length > 0 ? names.join(", ") : (status.vpnInterface ?? "VPN");
  return {
    tone: "ok",
    label: tunnels.length > 1 ? `${tunnels.length} VPNs connected` : "VPN connected",
    detail: `${where} · ${plural(status.routeCount, "route")}`,
  };
}
