"use client";

import { useQuery } from "@tanstack/react-query";
import { GitBranch, RefreshCw, Search, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import { HostCheckPanel } from "@/features/activity/host-check-panel";
import { useListNames } from "@/features/activity/list-names";
import type { RouteEntry } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";
import { filterRoutes, viasOf } from "./route-model";
import { RouteTable } from "./route-table";
import { ViaChips } from "./via-chips";

/** How often the open Routes tab refreshes. */
const ROUTES_REFRESH_MS = 2000;

/** Every route RouteWise added, which VPN it goes through, and the list entry it was added for. */
export function RoutesTab() {
  const [search, setSearch] = useState("");
  const [viaFilter, setViaFilter] = useState<string>();
  const names = useListNames();
  const routes = useQuery<RouteEntry[], RpcError>({
    queryKey: ["routes.list"],
    queryFn: () => rpc("routes.list"),
    refetchInterval: ROUTES_REFRESH_MS,
    refetchIntervalInBackground: false,
  });

  const all = useMemo(() => routes.data ?? [], [routes.data]);
  const vias = useMemo(() => viasOf(all), [all]);
  // The filtered tunnel went away: show every route again.
  const via = viaFilter !== undefined && vias.some((v) => v.id === viaFilter) ? viaFilter : undefined;
  const shown = useMemo(() => filterRoutes(all, search, via), [all, search, via]);

  return (
    <div className="flex h-full min-w-0 flex-col">
      <div className="px-0 pt-2">
        <HostCheckPanel />
      </div>
      <div className="flex items-center gap-2 border-t px-4 py-2">
        <div className="relative flex-1">
          <Search aria-hidden className="absolute top-2 left-2 size-4 text-muted-foreground" />
          <Input
            aria-label="Search routes"
            placeholder="Search domain, entry, IP, or VPN..."
            value={search}
            className="px-8"
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Refresh routes"
          title="Refresh routes"
          disabled={routes.isFetching}
          onClick={() => void routes.refetch()}>
          <RefreshCw className={routes.isFetching ? "animate-spin" : undefined} />
        </Button>
      </div>
      {vias.length > 0 ? (
        <ViaChips vias={vias} total={all.length} names={names} selected={via} onSelect={setViaFilter} />
      ) : null}

      {routes.isPending ? (
        <p className="flex flex-1 items-center justify-center text-sm text-muted-foreground">Loading...</p>
      ) : shown.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 text-muted-foreground">
          <GitBranch className="size-8" aria-hidden />
          <p className="text-sm">{all.length === 0 ? "No routes" : "No matching routes"}</p>
          {all.length === 0 ? (
            <p className="text-xs">Routes appear when a VPN is connected and an entry of its list resolves.</p>
          ) : null}
        </div>
      ) : (
        <RouteTable routes={shown} names={names} />
      )}

      {routes.isError ? (
        <p role="alert" className="flex items-center gap-1.5 p-3 text-xs text-destructive">
          <TriangleAlert className="size-3.5" aria-hidden />
          {featureErrorMessage(routes.error)}
        </p>
      ) : null}
    </div>
  );
}
