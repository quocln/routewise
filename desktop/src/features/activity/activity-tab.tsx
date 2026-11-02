"use client";

import { useMutation } from "@tanstack/react-query";
import { Activity, History, TriangleAlert, PauseCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { usePersistedState } from "@/lib/use-persisted-state";
import { rpc } from "@/lib/rpc/rpc-client";
import { useSettings, useStatus } from "@/lib/rpc/queries";
import { ActivityList } from "./activity-list";
import { ActivityToolbar } from "./activity-toolbar";
import { ACTIVITY_MODES, concernedVpn, type ActivityMode } from "./activity-event";
import { ACCESS_PAGE_SIZE } from "./activity-feed";
import { DEFAULT_FILTERS, accessParams, applyFilters, isActivityFilters, viaOptions } from "./activity-filters";
import { rowFromEntry, rowFromEvent } from "./activity-row";
import { ClearHistoryDialog } from "./clear-history-dialog";
import { featureErrorMessage } from "./helper-feature-error";
import { HostCheckPanel } from "./host-check-panel";
import { useListNames } from "./list-names";
import { useAccessStream } from "./use-access-stream";
import { useActivityStream } from "./use-activity-stream";

const SEGMENT_FALLBACK: ActivityMode = "connections";
const isMode = (value: unknown): value is ActivityMode => ACTIVITY_MODES.some((m) => m.value === value);

/** Long enough that typing a search does not query the helper on every key. */
const SEARCH_DEBOUNCE_MS = 300;

const FOOTER_NOTES: Record<ActivityMode, string> = {
  connections:
    "Connections are recorded when they start (TCP and QUIC). Apps using a proxy or DNS-over-HTTPS may show IPs without a domain.",
  dns: "DNS answers from the macOS cache and DNS-over-HTTPS lookups do not appear.",
  events: "What RouteWise did: VPN changes, routes added and removed, and addresses it refused to route.",
};

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

function EmptyState({ icon: Icon, text }: { icon: typeof History; text: string }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 text-muted-foreground">
      <Icon className="size-8" aria-hidden />
      <p className="text-sm">{text}</p>
    </div>
  );
}

/** What goes through the VPN: recorded connections, DNS answers, and routing events, under one set of filters. */
export function ActivityTab() {
  const [mode, setMode] = usePersistedState<ActivityMode>("activity.segment", SEGMENT_FALLBACK, isMode);
  const [filters, setFilters] = usePersistedState("activity.filters", DEFAULT_FILTERS, isActivityFilters);
  const [paused, setPaused] = useState(false);
  const [checkOpen, setCheckOpen] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearError, setClearError] = useState<string | null>(null);

  const names = useListNames();
  const status = useStatus();
  const settings = useSettings();

  // The helper filters Connections, so a keystroke waits; events are filtered here and follow at once.
  const search = useDebounced(filters.search, SEARCH_DEBOUNCE_MS);
  const { range, via, list } = filters;
  const params = useMemo(
    () => accessParams({ range, via, list, search }, ACCESS_PAGE_SIZE),
    [range, via, list, search],
  );
  const connections = useAccessStream(params, mode === "connections");
  const activity = useActivityStream({ enabled: mode !== "connections", paused });

  const clearHistory = useMutation({
    mutationFn: () => rpc("access.clear"),
    onSuccess: () => {
      setClearError(null);
      connections.reset();
    },
    onError: (error) => setClearError(`Could not clear history: ${featureErrorMessage(error)}`),
  });

  const tunnelNames = (status.data?.tunnels ?? []).map((t) => t.client.name);
  const seen = [
    ...connections.entries.flatMap((e) => (e.vpn ? [e.vpn] : [])),
    ...activity.events.flatMap((e) => concernedVpn(e) ?? []),
  ];
  const viaChoices = viaOptions(tunnelNames, seen, filters.via);

  const connectionRows = useMemo(() => {
    const now = new Date();
    return connections.entries.map((entry) => rowFromEntry(entry, names, now));
  }, [connections.entries, names]);
  const eventRows = useMemo(() => {
    const now = new Date();
    return applyFilters(activity.events, mode, filters, now).map((event) => rowFromEvent(event, names, now));
  }, [activity.events, mode, filters, names]);

  const rows = mode === "connections" ? connectionRows : eventRows;
  const error = mode === "connections" ? (clearError ?? connections.error) : activity.error;
  const helperReachable = !status.isError;

  return (
    <div className="flex h-full flex-col">
      <ActivityToolbar
        mode={mode}
        onModeChange={setMode}
        filters={filters}
        onFiltersChange={setFilters}
        names={names}
        via={viaChoices}
        canClearHistory={helperReachable}
        onClearHistory={() => setConfirmClear(true)}
        paused={paused}
        onPausedChange={setPaused}
        onClearEvents={activity.clear}
        checkOpen={checkOpen}
        onCheckOpenChange={setCheckOpen}
      />
      {checkOpen ? <HostCheckPanel /> : null}
      {mode === "connections" && settings.data?.historyEnabled === false ? (
        <p className="flex items-center gap-1.5 px-4 pb-1 text-xs text-orange-500">
          <PauseCircle className="size-3.5" aria-hidden />
          History recording is off. Turn it on in Settings.
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="flex items-center gap-1.5 px-4 pb-1 text-xs text-destructive">
          <TriangleAlert className="size-3.5" aria-hidden />
          {error}
        </p>
      ) : null}

      {rows.length > 0 ? (
        <ActivityList rows={rows} />
      ) : mode === "connections" ? (
        <EmptyState
          icon={History}
          text={connections.isLoading ? "Loading..." : "No connections recorded in this range"}
        />
      ) : (
        <EmptyState icon={Activity} text={activity.events.length === 0 ? "No activity yet" : "No matching activity"} />
      )}

      <div className="flex flex-col items-center gap-1 p-2">
        {mode === "connections" && connections.hasOlder ? (
          <Button variant="outline" size="xs" disabled={connections.isLoadingOlder} onClick={connections.loadOlder}>
            Load older
          </Button>
        ) : null}
        <p className="text-center text-xs text-muted-foreground">{FOOTER_NOTES[mode]}</p>
      </div>

      <ClearHistoryDialog
        open={confirmClear}
        onOpenChange={setConfirmClear}
        onConfirm={() => clearHistory.mutate()}
      />
    </div>
  );
}
