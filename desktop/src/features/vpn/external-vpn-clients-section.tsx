"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Settings, StatusResult, VPNClient } from "@/lib/api/types.gen";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { rpc } from "@/lib/rpc/rpc-client";
import { queryKeys } from "@/lib/rpc/queries";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { displayName, isBuiltInClientId, isClientConnected } from "./vpn-format";
import { useDomainCounts, useHelperReachable } from "./vpn-queries";

interface Props {
  clients: VPNClient[];
  status: StatusResult | undefined;
  onEditDomains?: (clientId: string) => void;
}

/**
 * VPN apps and command-line clients RouteWise was allowed to manage (the AWS
 * VPN Client, the WireGuard app, wg-quick, openvpn), in priority order.
 * Built-in profiles are allowed clients too, but have their own section.
 */
export function ExternalVPNClientsSection({ clients: allowed, status, onEditDomains }: Props) {
  const queryClient = useQueryClient();
  const helperReachable = useHelperReachable();
  const clients = allowed.filter((c) => !isBuiltInClientId(c.id));
  const counts = useDomainCounts(clients.map((c) => c.id));

  const remove = useMutation({
    mutationFn: (client: VPNClient) => rpc("vpn.setAllowed", { clientId: client.id, allowed: false }),
    onSuccess: (settings: Settings) => {
      queryClient.setQueryData(queryKeys.settings, settings);
      void queryClient.invalidateQueries({ queryKey: queryKeys.status });
    },
  });
  const error = remove.error
    ? `Could not remove ${remove.variables ? displayName(remove.variables.name, remove.variables.id) : "the VPN"}: ${helperFeatureErrorMessage(remove.error)}`
    : null;

  return (
    <section className="grid grid-cols-[minmax(0,1fr)] gap-3" aria-labelledby="vpn-apps-heading">
      <h2 id="vpn-apps-heading" className="text-sm font-semibold">
        VPN apps
      </h2>
      {clients.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          RouteWise asks before managing a VPN app. When it detects a full-tunnel VPN, it offers to manage it and
          remembers your answer here.
        </p>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            Priority order: when several are connected, &quot;Any VPN&quot; domains route through the first.
          </p>
          <ul className="grid grid-cols-[minmax(0,1fr)] gap-2">
            {clients.map((client, index) => {
              const connected = isClientConnected(client.id, status);
              const count = counts[client.id];
              return (
                <li key={client.id} className="flex items-center gap-3 rounded-lg border p-2.5">
                  <span className="w-5 text-center text-sm font-semibold text-muted-foreground tabular-nums">
                    {index + 1}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 text-sm">
                      <span className="truncate">{displayName(client.name, client.id)}</span>
                      <span
                        className={cn("size-1.5 shrink-0 rounded-full", connected ? "bg-emerald-500" : "bg-muted-foreground")}
                        aria-hidden
                      />
                      <span className="text-xs text-muted-foreground">{connected ? "Connected" : "Not connected"}</span>
                    </div>
                    <p className="truncate font-mono text-xs text-muted-foreground" title={client.id}>
                      {client.id}
                    </p>
                  </div>
                  {count !== undefined ? (
                    <span className={cn("text-xs", count === 0 ? "text-orange-600 dark:text-orange-400" : "text-muted-foreground")}>
                      {count === 1 ? "1 entry" : `${count} entries`}
                    </span>
                  ) : null}
                  {onEditDomains ? (
                    <Button
                      variant="outline"
                      size="sm"
                      title={`Edit the domains that go through ${client.name}`}
                      onClick={() => onEditDomains(client.id)}>
                      Domains
                    </Button>
                  ) : null}
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!helperReachable || remove.isPending}
                    title="Stop managing this VPN; its domain list is deleted"
                    onClick={() => remove.mutate(client)}>
                    Remove
                  </Button>
                </li>
              );
            })}
          </ul>
        </>
      )}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
