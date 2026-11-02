import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import type { Entry as AccessEntry } from "@/lib/api/history.gen";
import {
  addressesOf,
  concernedVpn,
  isUnroutedIPv6Answer,
  isVpnAddress,
  parseTime,
} from "./activity-event";
import { ANY_VPN_ID, type ListGroup, type ListNames } from "./list-names";

/** Where traffic went. */
export type RowRoute = { kind: "vpn"; client?: string } | { kind: "direct" } | { kind: "other" };

/** One row of the Activity tab, whatever it came from: a recorded connection or an activity event. */
export interface ActivityRow {
  id: string;
  time: string;
  /** The event kind, for its icon; undefined for a connection. */
  kind?: string;
  /** The name, or the address when there is none. */
  title: string;
  /** `ip:port` of a connection, or the addresses of an event. */
  endpoint?: string;
  /** "TCP" or "UDP"; undefined for an event. */
  proto?: string;
  rule?: string;
  list?: string;
  listTitle?: string;
  listGroup?: ListGroup;
  /** The event's own explanation ("answered by 1.1.1.1", why it was refused). */
  detail?: string;
  route?: RowRoute;
  /** Why a listed name did not go through its VPN, as a sentence and a short label. */
  warning?: string;
  warningLabel?: string;
  /** Something worth knowing that is not a fault, as a sentence and a short label. */
  notice?: string;
  noticeLabel?: string;
}

/** Addresses an event row shows before the rest are left to the detail. */
export const MAX_ADDRESSES = 2;

const pad = (n: number) => String(n).padStart(2, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `HH:mm:ss`, preceded by the date (`MMM d`) when `date` is not today. */
export function formatTime(date: Date, now: Date = new Date()): string {
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  const sameDay =
    date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth() && date.getDate() === now.getDate();
  return sameDay ? clock : `${MONTHS[date.getMonth()]} ${date.getDate()} ${clock}`;
}

function timeOf(time: string, now: Date): string {
  const date = parseTime(time);
  return date ? formatTime(date, now) : time;
}

/** `host:port`, with an IPv6 address bracketed. */
export function endpointOf(entry: AccessEntry): string {
  return entry.ip.includes(":") ? `[${entry.ip}]:${entry.port}` : `${entry.ip}:${entry.port}`;
}

interface Mismatch {
  sentence: string;
  label: string;
}

/** Why something that matched a list did not go through its VPN, or undefined when it did (or matched no list). */
export function mismatch(list: string | undefined | null, wentViaVpn: boolean, names: ListNames): Mismatch | undefined {
  if (list == null || wentViaVpn) return undefined;
  if (list === ANY_VPN_ID) {
    return { sentence: "In the Any VPN list, but no VPN app was connected, so it went direct.", label: "no VPN" };
  }
  const title = names.title(list);
  return { sentence: `In ${title}'s list, but ${title} was not connected, so it went direct.`, label: `${title} off` };
}

function listFields(list: string | undefined | null, names: ListNames) {
  return list == null
    ? {}
    : { list, listTitle: names.title(list), listGroup: names.group(list) };
}

function entryRoute(entry: AccessEntry): RowRoute {
  if (entry.verdict === "vpn") return { kind: "vpn", client: entry.vpn || undefined };
  return { kind: entry.verdict === "direct" ? "direct" : "other" };
}

/** The row of a recorded connection. */
export function rowFromEntry(entry: AccessEntry, names: ListNames, now: Date = new Date()): ActivityRow {
  const missed = mismatch(entry.list, entry.verdict === "vpn", names);
  return {
    id: `c${entry.id}`,
    time: timeOf(entry.time, now),
    title: entry.name || entry.ip,
    endpoint: endpointOf(entry),
    proto: entry.proto.toUpperCase(),
    rule: entry.rule || undefined,
    ...listFields(entry.list, names),
    route: entryRoute(entry),
    warning: missed?.sentence,
    warningLabel: missed?.label,
  };
}

const IPV6_BLOCKED_NOTICE =
  "RouteWise blocks the IPv6 addresses of listed domains, so apps connect over IPv4, which goes through the VPN. " +
  "Settings › IPv6 turns this off.";

function eventNotice(event: ActivityEvent, unroutedIPv6: boolean, names: ListNames) {
  if (!unroutedIPv6) return {};
  if (addressesOf(event).every((a) => a.blocked === true)) {
    return { notice: IPV6_BLOCKED_NOTICE, noticeLabel: "IPv6 blocked" };
  }
  if (event.list != null) {
    return {
      notice:
        `RouteWise routes IPv4 only, so this IPv6 answer does not go through ${names.title(event.list)}. ` +
        "On a network with IPv6, apps that use it go direct.",
      noticeLabel: "IPv6 not routed",
    };
  }
  return {};
}

function eventRoute(event: ActivityEvent, wentViaVpn: boolean, unroutedIPv6: boolean): RowRoute | undefined {
  const vpn = concernedVpn(event);
  // A removed route goes nowhere; an unrouted IPv6 answer depends on the network, not on RouteWise.
  if (event.kind === "route_removed" || unroutedIPv6) return undefined;
  if (addressesOf(event).length === 0 && vpn === undefined) return undefined;
  return wentViaVpn ? { kind: "vpn", client: vpn } : { kind: "direct" };
}

/** The row of an activity event. */
export function rowFromEvent(event: ActivityEvent, names: ListNames, now: Date = new Date()): ActivityRow {
  const addresses = addressesOf(event);
  const shown = addresses.slice(0, MAX_ADDRESSES).map((a) => a.ip);
  const more = addresses.length - shown.length;
  const vpn = concernedVpn(event);
  const wentViaVpn = vpn !== undefined || addresses.some(isVpnAddress);
  const unroutedIPv6 = isUnroutedIPv6Answer(event) && vpn === undefined;
  // Only a DNS answer says where a name goes. An AAAA answer is not a list that
  // went direct: its VPN may be up, and RouteWise never routes IPv6.
  const missed = event.kind === "dns" && !unroutedIPv6 ? mismatch(event.list, wentViaVpn, names) : undefined;
  return {
    id: `e${event.seq}`,
    time: timeOf(event.time, now),
    kind: event.kind,
    title: event.name || addresses[0]?.ip || "",
    endpoint: shown.length === 0 ? undefined : shown.join(", ") + (more > 0 ? ` +${more}` : ""),
    rule: event.rule || undefined,
    ...listFields(event.list, names),
    detail: event.detail || undefined,
    route: eventRoute(event, wentViaVpn, unroutedIPv6),
    warning: missed?.sentence,
    warningLabel: missed?.label,
    ...eventNotice(event, unroutedIPv6, names),
  };
}
