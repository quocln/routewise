import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import type { AccessListParams } from "@/lib/api/types.gen";
import {
  addressesOf,
  concernedVpn,
  isUnroutedIPv6Answer,
  isVpnAddress,
  modeIncludes,
  parseTime,
  type ActivityMode,
} from "./activity-event";

export const HISTORY_RANGES = [
  { value: "lastHour", label: "Last hour" },
  { value: "today", label: "Today" },
  { value: "last24Hours", label: "Last 24 hours" },
  { value: "last7Days", label: "Last 7 days" },
] as const;

export type HistoryRange = (typeof HISTORY_RANGES)[number]["value"];

const HOUR_MS = 3_600_000;

/** Start of the range in epoch milliseconds; every range ends now. */
export function sinceMs(range: HistoryRange, now: Date = new Date()): number {
  switch (range) {
    case "lastHour":
      return now.getTime() - HOUR_MS;
    case "today":
      return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    case "last24Hours":
      return now.getTime() - 24 * HOUR_MS;
    case "last7Days":
      return now.getTime() - 7 * 24 * HOUR_MS;
  }
}

/** The "Via" filter: where the traffic went. */
export type ActivityVia =
  | { kind: "all" }
  | { kind: "direct" }
  | { kind: "vpn"; name: string }
  | { kind: "other" };

export const VIA_ALL: ActivityVia = { kind: "all" };

export function viaLabel(via: ActivityVia): string {
  switch (via.kind) {
    case "all":
      return "All";
    case "direct":
      return "Direct";
    case "vpn":
      return via.name;
    case "other":
      return "Other";
  }
}

/** The picker's choices: All, Direct, every known or selected VPN, then Other. */
export function viaOptions(tunnelNames: string[], seen: string[], selected: ActivityVia): ActivityVia[] {
  const names = new Set([...tunnelNames, ...seen]);
  if (selected.kind === "vpn") names.add(selected.name);
  names.delete("");
  const sorted = [...names].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "accent" }));
  return [{ kind: "all" }, { kind: "direct" }, ...sorted.map((name): ActivityVia => ({ kind: "vpn", name })), { kind: "other" }];
}

/** The toolbar every Activity mode shares. */
export interface ActivityFilters {
  range: HistoryRange;
  via: ActivityVia;
  /** Only entries that matched this list (a client id, "" for Any VPN); null applies no filter. */
  list: string | null;
  search: string;
}

/** Today, every source, no search: what the tab starts with. */
export const DEFAULT_FILTERS: ActivityFilters = { range: "today", via: VIA_ALL, list: null, search: "" };

/** The search text trimmed, or undefined when blank. */
export function trimmedSearch(filters: ActivityFilters): string | undefined {
  const trimmed = filters.search.trim();
  return trimmed === "" ? undefined : trimmed;
}

function viaParams(via: ActivityVia): Pick<AccessListParams, "verdict" | "vpn"> {
  if (via.kind === "direct" || via.kind === "other") return { verdict: via.kind };
  if (via.kind === "vpn") return { vpn: via.name };
  return {};
}

/** Params of the access.list load behind Connections. */
export function accessParams(filters: ActivityFilters, limit: number, now: Date = new Date()): AccessListParams {
  const params: AccessListParams = {
    sinceMs: sinceMs(filters.range, now),
    limit,
    ...viaParams(filters.via),
  };
  const search = trimmedSearch(filters);
  if (search !== undefined) params.search = search;
  if (filters.list !== null) params.list = filters.list;
  return params;
}

function contains(value: string | undefined, query: string): boolean {
  return value !== undefined && value.toLowerCase().includes(query);
}

function matchesVia(event: ActivityEvent, via: ActivityVia): boolean {
  const addresses = addressesOf(event);
  switch (via.kind) {
    case "all":
      return true;
    case "direct":
      return (
        concernedVpn(event) === undefined &&
        addresses.length > 0 &&
        !addresses.some(isVpnAddress) &&
        !isUnroutedIPv6Answer(event)
      );
    case "vpn":
      return concernedVpn(event) === via.name;
    case "other":
      // "Other" names a tunnel the helper does not manage, which no event records.
      return false;
  }
}

/** Whether an activity event passes every filter (not the mode). */
export function matchesEvent(event: ActivityEvent, filters: ActivityFilters, now: Date = new Date()): boolean {
  const date = parseTime(event.time);
  if (date && date.getTime() < sinceMs(filters.range, now)) return false;
  if (filters.list !== null && event.list !== filters.list) return false;
  if (!matchesVia(event, filters.via)) return false;
  const query = trimmedSearch(filters)?.toLowerCase();
  if (query === undefined) return true;
  return (
    [event.name, event.detail, event.rule, event.vpn].some((v) => contains(v, query)) ||
    addressesOf(event).some((a) => contains(a.ip, query))
  );
}

/** The events `mode` lists that pass the filters, in their given order. */
export function applyFilters(
  events: ActivityEvent[],
  mode: ActivityMode,
  filters: ActivityFilters,
  now: Date = new Date(),
): ActivityEvent[] {
  return events.filter((e) => modeIncludes(mode, e.kind) && matchesEvent(e, filters, now));
}

const RANGE_VALUES: readonly unknown[] = HISTORY_RANGES.map((r) => r.value);

function isVia(value: unknown): value is ActivityVia {
  if (typeof value !== "object" || value === null || !("kind" in value)) return false;
  if (value.kind === "vpn") return "name" in value && typeof value.name === "string";
  return value.kind === "all" || value.kind === "direct" || value.kind === "other";
}

/** Guard for filters read back from storage. */
export function isActivityFilters(value: unknown): value is ActivityFilters {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    RANGE_VALUES.includes(v.range) &&
    isVia(v.via) &&
    (v.list === null || typeof v.list === "string") &&
    typeof v.search === "string"
  );
}
