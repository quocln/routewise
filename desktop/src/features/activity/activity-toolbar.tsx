"use client";

import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ACTIVITY_MODES, type ActivityMode } from "./activity-event";
import {
  HISTORY_RANGES,
  viaLabel,
  type ActivityFilters,
  type ActivityVia,
  type HistoryRange,
} from "./activity-filters";
import type { ListNames } from "./list-names";
import { OptionSelect, type Option } from "./option-select";

const ALL = "all";
const LIST_PREFIX = "list:";
const VPN_PREFIX = "vpn:";

const encodeVia = (via: ActivityVia): string => (via.kind === "vpn" ? VPN_PREFIX + via.name : via.kind);
function decodeVia(value: string): ActivityVia {
  if (value.startsWith(VPN_PREFIX)) return { kind: "vpn", name: value.slice(VPN_PREFIX.length) };
  return value === "direct" || value === "other" ? { kind: value } : { kind: "all" };
}

export interface ActivityToolbarProps {
  mode: ActivityMode;
  onModeChange: (mode: ActivityMode) => void;
  filters: ActivityFilters;
  onFiltersChange: (filters: ActivityFilters) => void;
  names: ListNames;
  via: ActivityVia[];
  /** Connections: whether the helper can be asked to delete the history. */
  canClearHistory: boolean;
  onClearHistory: () => void;
  paused: boolean;
  onPausedChange: (paused: boolean) => void;
  onClearEvents: () => void;
  checkOpen: boolean;
  onCheckOpenChange: (open: boolean) => void;
}

/** Segments, the mode's buttons, and the filters every mode shares. */
export function ActivityToolbar(props: ActivityToolbarProps) {
  const { mode, filters, onFiltersChange: change } = props;
  const rangeOptions: Option[] = HISTORY_RANGES.map((r) => ({ value: r.value, label: r.label }));
  const listOptions: Option[] = [
    { value: ALL, label: "All" },
    ...props.names.items.map((item) => ({ value: LIST_PREFIX + item.id, label: item.title })),
  ];
  // A stored list that no longer exists must still be a choice, so the select never holds an unlisted value.
  if (filters.list !== null && !listOptions.some((o) => o.value === LIST_PREFIX + filters.list)) {
    listOptions.push({ value: LIST_PREFIX + filters.list, label: props.names.title(filters.list) });
  }
  const viaOptions: Option[] = props.via.map((via) => ({ value: encodeVia(via), label: viaLabel(via) }));

  return (
    <div className="flex flex-col gap-2 px-4 pt-3 pb-2">
      <div className="flex items-center justify-between gap-2">
        <Tabs value={mode} onValueChange={(value) => props.onModeChange(value as ActivityMode)}>
          <TabsList>
            {ACTIVITY_MODES.map((m) => (
              <TabsTrigger key={m.value} value={m.value}>
                {m.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <div className="flex items-center gap-2">
          <Button
            variant={props.checkOpen ? "secondary" : "outline"}
            size="sm"
            aria-expanded={props.checkOpen}
            onClick={() => props.onCheckOpenChange(!props.checkOpen)}>
            Check host
          </Button>
          {mode === "connections" ? (
            <Button variant="outline" size="sm" disabled={!props.canClearHistory} onClick={props.onClearHistory}>
              Clear History
            </Button>
          ) : (
            <>
              <Button
                variant={props.paused ? "secondary" : "outline"}
                size="sm"
                aria-pressed={props.paused}
                onClick={() => props.onPausedChange(!props.paused)}>
                {props.paused ? "Resume" : "Pause"}
              </Button>
              <Button variant="outline" size="sm" onClick={props.onClearEvents}>
                Clear
              </Button>
            </>
          )}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <OptionSelect
          label="Range"
          value={filters.range}
          options={rangeOptions}
          onValueChange={(range) => change({ ...filters, range: range as HistoryRange })}
          className="w-40"
        />
        <OptionSelect
          label="List"
          help="Show only what matched an entry of this list"
          value={filters.list === null ? ALL : LIST_PREFIX + filters.list}
          options={listOptions}
          onValueChange={(value) =>
            change({ ...filters, list: value === ALL ? null : value.slice(LIST_PREFIX.length) })
          }
          className="w-40"
        />
        <OptionSelect
          label="Via"
          help="Show only traffic that went this way"
          value={encodeVia(filters.via)}
          options={viaOptions}
          onValueChange={(value) => change({ ...filters, via: decodeVia(value) })}
          className="w-40"
        />
        <div className="relative min-w-48 flex-1">
          <Search className="absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={filters.search}
            onChange={(e) => change({ ...filters, search: e.target.value })}
            placeholder="Search name, IP, or entry..."
            aria-label="Search"
            className="h-7 pl-8"
          />
        </div>
      </div>
    </div>
  );
}
