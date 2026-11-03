"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { SetSettingsParams, Settings, StatusResult, VPNClient } from "@/lib/api/types.gen";
import { OptionSelect } from "@/features/activity/option-select";
import { queryKeys } from "@/lib/rpc/queries";
import { rpc } from "@/lib/rpc/rpc-client";
import { DefaultVPNExceptions } from "./default-vpn-exceptions";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { useHelperReachable } from "./vpn-queries";

// A select needs a value for "none"; a client id is a path or a prefixed id, so
// these never collide with one.
const OFF = "off";
const DIRECT = "direct";

function currentRouteText(status: StatusResult | undefined): string | null {
  const current = status?.defaultVpn;
  if (!current) return null;
  switch (current.state) {
    case "primary":
      return `Other traffic goes through ${current.activeClient} (${current.activeInterface}).`;
    case "fallback":
      return `The default VPN is unavailable. Other traffic goes through ${current.activeClient} (${current.activeInterface}).`;
    default:
      return current.problem ? "Other traffic goes direct." : "The default VPN is not connected. Other traffic goes direct.";
  }
}

/**
 * Picks the VPN that carries traffic no connected VPN's list claims, built-in or
 * app alike, and what happens to that traffic while it is down. It writes through
 * settings.set and shows only what the helper reports, so it never claims a route
 * the helper did not install.
 */
export function DefaultVPNSection({
  clients,
  settings,
  status,
}: {
  clients: VPNClient[];
  settings: Settings | undefined;
  status: StatusResult | undefined;
}) {
  const queryClient = useQueryClient();
  const helperReachable = useHelperReachable();
  const save = useMutation({
    mutationFn: (params: SetSettingsParams) => rpc("settings.set", params),
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.status }),
        queryClient.invalidateQueries({ queryKey: queryKeys.settings }),
      ]);
    },
  });

  // The helper reports the setting only from the version that has it.
  const supported = typeof settings?.defaultVpn === "string";
  const exceptionsSupported = Array.isArray(settings?.defaultVpnExcept);
  const chosen = save.isPending ? (save.variables.defaultVpn ?? settings?.defaultVpn) : settings?.defaultVpn;
  const fallback = save.isPending
    ? (save.variables.defaultVpnFallback ?? settings?.defaultVpnFallback)
    : settings?.defaultVpnFallback;
  const disabled = !helperReachable || !supported || save.isPending;
  const routeText = currentRouteText(status);

  const choose = (value: string) => {
    if (value === OFF) {
      save.mutate({ defaultVpn: "", defaultVpnFallback: "" });
      return;
    }
    // A fallback equal to the new default would be refused, so it goes with the change.
    save.mutate(value === fallback ? { defaultVpn: value, defaultVpnFallback: "" } : { defaultVpn: value });
  };

  return (
    <section className="grid grid-cols-[minmax(0,1fr)] gap-3" aria-labelledby="default-vpn-heading">
      <h2 id="default-vpn-heading" className="text-sm font-semibold">
        Default VPN
      </h2>
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,16rem)] items-center gap-x-3 gap-y-2 text-sm">
        <span>Send other traffic through</span>
        <OptionSelect
          label="Default VPN"
          value={chosen || OFF}
          disabled={disabled}
          options={[{ value: OFF, label: "No VPN (direct)" }, ...clients.map((c) => ({ value: c.id, label: c.name }))]}
          onValueChange={choose}
        />
        <span>If it goes down</span>
        <OptionSelect
          label="If the default VPN goes down"
          value={fallback || DIRECT}
          disabled={disabled || !chosen}
          options={[
            { value: DIRECT, label: "Go direct" },
            ...clients.filter((c) => c.id !== chosen).map((c) => ({ value: c.id, label: `Switch to ${c.name}` })),
          ]}
          onValueChange={(value) => save.mutate({ defaultVpnFallback: value === DIRECT ? "" : value })}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        Traffic that is in no list goes through this VPN. Listed domains keep their own VPN; while that VPN is down they
        follow the default VPN too. IPv6 is blocked while a default VPN carries traffic, unless you allow it in Settings.
      </p>
      {exceptionsSupported ? (
        <DefaultVPNExceptions
          entries={settings?.defaultVpnExcept ?? []}
          disabled={disabled || !chosen}
          onChange={(next) => save.mutateAsync({ defaultVpnExcept: next })}
        />
      ) : null}
      {routeText ? <p className="text-xs text-muted-foreground">{routeText}</p> : null}
      {status?.defaultVpn?.problem ? (
        <p role="alert" className="text-xs text-orange-600 dark:text-orange-400">
          {status.defaultVpn.problem}
        </p>
      ) : null}
      {settings && !supported ? (
        <p className="text-xs text-orange-600 dark:text-orange-400">Needs a newer RouteWise helper.</p>
      ) : null}
      {save.error ? (
        <p role="alert" className="text-xs text-destructive">
          Could not change the default VPN: {helperFeatureErrorMessage(save.error)}
        </p>
      ) : null}
    </section>
  );
}
