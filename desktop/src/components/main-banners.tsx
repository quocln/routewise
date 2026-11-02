"use client";

import { PendingVPNBanner } from "@/features/vpn/pending-vpn-banner";
import { useStatus } from "@/lib/rpc/queries";

/**
 * What needs the user's attention whichever tab is open: a detected full-tunnel
 * VPN that RouteWise is not managing. Its own component, so a status refresh
 * redraws these banners and not the tabs.
 */
export function MainBanners() {
  const { data: status } = useStatus();
  const pending = status?.pendingVpns ?? (status?.pendingVpn ? [status.pendingVpn] : []);
  if (pending.length === 0) return null;
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2 px-4 pt-3">
      {pending.map((vpn) => (
        <PendingVPNBanner key={`${vpn.interface}:${vpn.client.id}`} pending={vpn} />
      ))}
    </div>
  );
}
