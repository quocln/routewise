"use client";

import { useSettings, useStatus } from "@/lib/rpc/queries";
import { BuiltInVPNsSection } from "./built-in-vpns-section";
import { DefaultVPNSection } from "./default-vpn-section";
import { ExternalVPNClientsSection } from "./external-vpn-clients-section";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { VPNDNSSection } from "./vpn-dns-section";

interface Props {
  /** Opens the Domains tab on a VPN's list. Without it the "Edit Domains" controls are hidden. */
  onEditDomains?: (clientId: string) => void;
}

/**
 * The VPN tab: built-in WireGuard, Outline and proxy profiles, the VPN apps RouteWise
 * manages, and the VPN DNS switch.
 */
export function VpnTab({ onEditDomains }: Props) {
  const { data: status } = useStatus();
  const settings = useSettings();
  // An unreachable helper is already said by the status header.
  const settingsError =
    settings.error && !settings.error.isUnavailable
      ? `Could not load VPN clients: ${helperFeatureErrorMessage(settings.error)}`
      : null;

  return (
    <div className="h-full overflow-y-auto" data-testid="vpn-tab">
      <div className="mx-auto grid max-w-3xl grid-cols-[minmax(0,1fr)] gap-6 p-4">
        <BuiltInVPNsSection status={status} onEditDomains={onEditDomains} />
        <ExternalVPNClientsSection
          clients={settings.data?.allowedVpnClients ?? []}
          status={status}
          onEditDomains={onEditDomains}
        />
        <DefaultVPNSection clients={settings.data?.allowedVpnClients ?? []} settings={settings.data} status={status} />
        <VPNDNSSection status={status} />
        {settingsError ? (
          <p role="alert" className="text-xs text-destructive">
            {settingsError}
          </p>
        ) : null}
      </div>
    </div>
  );
}
