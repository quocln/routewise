"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { StatusResult } from "@/lib/api/types.gen";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { rpc } from "@/lib/rpc/rpc-client";
import { queryKeys } from "@/lib/rpc/queries";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { useHelperReachable } from "./vpn-queries";

/**
 * The "Use the VPN's DNS servers" switch. It reads the helper's live value and
 * writes through settings.set, so it never shows a value the helper did not apply.
 */
export function VPNDNSSection({ status }: { status: StatusResult | undefined }) {
  const queryClient = useQueryClient();
  const helperReachable = useHelperReachable();
  const save = useMutation({
    mutationFn: (enabled: boolean) => rpc("settings.set", { useVpnDns: enabled }),
    onSettled: async () => {
      // Settled, not just succeeded: after a failure the switch falls back to what the helper reports.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.status }),
        queryClient.invalidateQueries({ queryKey: queryKeys.settings }),
      ]);
    },
  });

  // While a change is being saved the switch shows the requested value, so it
  // neither snaps back nor greys out.
  const checked = save.isPending ? save.variables : (status?.useVpnDns ?? false);
  const servers = status?.vpnDnsServers ?? [];

  return (
    <section className="grid grid-cols-[minmax(0,1fr)] gap-3" aria-labelledby="vpn-dns-heading">
      <h2 id="vpn-dns-heading" className="text-sm font-semibold">
        DNS
      </h2>
      <div className="flex items-center gap-2">
        <Switch
          id="use-vpn-dns"
          checked={checked}
          disabled={!helperReachable}
          onCheckedChange={(enabled) => !save.isPending && save.mutate(enabled)}
        />
        <Label htmlFor="use-vpn-dns" className="font-normal">
          Use the VPN&apos;s DNS servers
        </Label>
        {save.isPending ? <span className="text-xs text-muted-foreground">Saving…</span> : null}
      </div>
      {!helperReachable ? (
        <p className="text-xs text-orange-600 dark:text-orange-400">
          Unavailable until the app reconnects to the RouteWise helper.
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        Resolve configured domains and wildcard names through the DNS servers your VPN provides. Turn this on when
        internal names exist only in company DNS. The VPN&apos;s DNS servers stay reachable through the tunnel either
        way.
      </p>
      {servers.length > 0 ? <p className="text-xs text-muted-foreground">VPN DNS: {servers.join(", ")}</p> : null}
      {save.error ? (
        <p role="alert" className="text-xs text-destructive">
          Could not change VPN DNS: {helperFeatureErrorMessage(save.error)}
        </p>
      ) : null}
    </section>
  );
}
