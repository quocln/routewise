"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlertIcon } from "lucide-react";
import type { PendingVPN, Settings } from "@/lib/api/types.gen";
import { Button } from "@/components/ui/button";
import { rpc } from "@/lib/rpc/rpc-client";
import { queryKeys } from "@/lib/rpc/queries";
import { helperFeatureErrorMessage } from "./vpn-errors";

/** Offers to manage a detected full-tunnel VPN whose client is not on the allowlist. */
export function PendingVPNBanner({ pending }: { pending: PendingVPN }) {
  const queryClient = useQueryClient();
  const canManage = pending.client.id !== "";
  const manage = useMutation({
    mutationFn: () => rpc("vpn.setAllowed", { clientId: pending.client.id, allowed: true }),
    onSuccess: (settings: Settings) => {
      queryClient.setQueryData(queryKeys.settings, settings);
      void queryClient.invalidateQueries({ queryKey: queryKeys.status });
    },
  });

  return (
    <div role="region" aria-label="VPN not managed" className="grid grid-cols-[minmax(0,1fr)] gap-1.5 rounded-lg bg-orange-500/10 p-3">
      <p className="flex items-start gap-1.5 text-xs font-semibold text-orange-600 dark:text-orange-400">
        <ShieldAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
        {pending.client.name} VPN on {pending.interface} detected — RouteWise is not managing it
      </p>
      <p className="text-xs text-muted-foreground">
        Managing it sends only your configured domains through the VPN. Everything else goes direct.
      </p>
      <div>
        <Button size="sm" disabled={!canManage || manage.isPending} onClick={() => manage.mutate()}>
          {manage.isPending ? "Managing…" : "Manage this VPN"}
        </Button>
      </div>
      {!canManage ? (
        <p className="text-xs text-muted-foreground">
          RouteWise could not identify the client that owns this VPN, so it cannot manage it.
        </p>
      ) : null}
      {manage.error ? (
        <p role="alert" className="text-xs text-destructive">
          {helperFeatureErrorMessage(manage.error)}
        </p>
      ) : null}
    </div>
  );
}
