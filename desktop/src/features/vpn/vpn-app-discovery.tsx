"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Settings, VPNClient } from "@/lib/api/types.gen";
import { Button } from "@/components/ui/button";
import { pickVPNProgram } from "@/lib/native/native-commands";
import { queryKeys } from "@/lib/rpc/queries";
import { rpc } from "@/lib/rpc/rpc-client";
import { helperFeatureErrorMessage } from "./vpn-errors";

interface Props {
  /** The clients already allowed, which a scan result stops offering once it joins them. */
  allowedIds: string[];
  disabled: boolean;
}

/**
 * Finds VPN apps before they connect, so a list or the default VPN can be set up
 * ahead of time. Scanning only suggests: nothing is managed until it is chosen,
 * and choosing a program is itself that choice.
 */
export function VPNAppDiscovery({ allowedIds, disabled }: Props) {
  const queryClient = useQueryClient();
  const saved = (settings: Settings) => {
    queryClient.setQueryData(queryKeys.settings, settings);
    void queryClient.invalidateQueries({ queryKey: queryKeys.status });
  };

  const scan = useMutation({ mutationFn: () => rpc("vpn.scan") });
  const allow = useMutation({
    mutationFn: (client: VPNClient) => rpc("vpn.setAllowed", { clientId: client.id, allowed: true }),
    onSuccess: saved,
  });
  const add = useMutation({
    mutationFn: async () => {
      const path = await pickVPNProgram();
      if (path === null) return null;
      // The helper names what owns the tunnel, which is rarely the app itself.
      const client = await rpc("vpn.resolve", { path });
      return rpc("vpn.setAllowed", { clientId: client.id, allowed: true });
    },
    onSuccess: (settings) => {
      if (settings) saved(settings);
    },
  });

  const found = scan.data?.clients.filter((c) => !allowedIds.includes(c.id));
  const failure = scan.error ?? allow.error ?? add.error;
  const busy = scan.isPending || allow.isPending || add.isPending;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" size="sm" disabled={disabled || busy} onClick={() => scan.mutate()}>
          {scan.isPending ? "Scanning..." : "Scan for VPN apps"}
        </Button>
        <Button variant="outline" size="sm" disabled={disabled || busy} onClick={() => add.mutate()}>
          {add.isPending ? "Adding..." : "Add app..."}
        </Button>
      </div>
      {found?.length === 0 ? <p className="text-xs text-muted-foreground">No new VPN apps found.</p> : null}
      {found?.length ? (
        <>
          <p className="text-xs text-muted-foreground">
            Found on this computer. RouteWise starts managing one you add the next time it connects.
          </p>
          <ul className="grid grid-cols-[minmax(0,1fr)] gap-2" aria-label="VPN apps found">
            {found.map((client) => (
              <li key={client.id} className="flex items-center gap-3 rounded-lg border p-2.5">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm">{client.name}</p>
                  <p className="truncate font-mono text-xs text-muted-foreground" title={client.id}>
                    {client.id}
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={disabled || busy}
                  title={`Let RouteWise manage ${client.name}`}
                  onClick={() => allow.mutate(client)}>
                  Manage
                </Button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {failure ? (
        <p role="alert" className="text-xs text-destructive">
          {helperFeatureErrorMessage(failure)}
        </p>
      ) : null}
    </div>
  );
}
