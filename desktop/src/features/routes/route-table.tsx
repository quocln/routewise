"use client";

import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useRef } from "react";
import { MatchedEntry } from "@/features/activity/activity-row-view";
import type { ListNames } from "@/features/activity/list-names";
import type { RouteEntry } from "@/lib/api/types.gen";
import { cn } from "@/lib/utils";
import { formatAddedAt, isVpnRoute, vpnTitle } from "./route-model";

const ROW_HEIGHT = 32;

/** Destination, matched entry, via, IP, gateway, added: one grid for the header and every row. */
const COLUMNS =
  "grid grid-cols-[minmax(140px,1.4fr)_minmax(140px,1.8fr)_minmax(110px,1.1fr)_minmax(100px,0.9fr)_minmax(80px,0.8fr)_64px] items-center gap-3";

const HEADERS = ["Destination", "Matched entry", "Via", "IP", "Gateway", "Added"];

interface RowProps {
  route: RouteEntry;
  names: ListNames;
}

const RouteRow = memo(function RouteRow({ route, names }: RowProps) {
  const vpn = isVpnRoute(route);
  const title = vpnTitle(names, route.clientId, route.vpn) ?? (vpn ? "VPN" : "Local");
  const matched = route.list == null ? undefined : { title: names.title(route.list), group: names.group(route.list) };
  return (
    <div className={cn(COLUMNS, "h-full px-4 text-sm")} data-testid="route-row">
      <span className="truncate font-mono" title={route.domain || route.ip}>
        {route.domain || route.ip}
      </span>
      <MatchedEntry
        title={matched?.title}
        group={matched?.group}
        rule={route.rule}
        placeholder={route.protected ? "VPN DNS server" : "—"}
      />
      <span className="flex min-w-0 items-center gap-1.5 whitespace-nowrap">
        <span aria-hidden className={cn("size-2 shrink-0 rounded-full", vpn ? "bg-green-500" : "bg-blue-500")} />
        <span className="truncate">{title}</span>
        {route.interface ? <span className="shrink-0 text-xs text-muted-foreground">{route.interface}</span> : null}
      </span>
      <span className="truncate font-mono">{route.ip}</span>
      <span className="truncate font-mono text-xs text-muted-foreground">{route.gateway}</span>
      <span className="truncate text-muted-foreground">{formatAddedAt(route.addedAt)}</span>
    </div>
  );
});

/** The routes in a virtualised table: only the rows in view are in the DOM. */
export function RouteTable({ routes, names }: { routes: readonly RouteEntry[]; names: ListNames }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  // The virtualizer is not memoised by the React Compiler, which is fine: it is read only here.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: routes.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    getItemKey: (index) => routes[index].ip,
  });
  return (
    <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto" data-testid="routes-scroll">
      <div className="min-w-[760px]">
        <div
          role="row"
          className={cn(COLUMNS, "sticky top-0 z-10 border-b bg-background px-4 py-1.5 text-xs font-medium text-muted-foreground")}>
          {HEADERS.map((header) => (
            <span key={header} role="columnheader">
              {header}
            </span>
          ))}
        </div>
        <ul className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((item) => (
            <li
              key={item.key}
              className="absolute inset-x-0 border-b"
              style={{ height: item.size, transform: `translateY(${item.start}px)` }}>
              <RouteRow route={routes[item.index]} names={names} />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
