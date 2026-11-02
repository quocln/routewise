import type { Address, Event as ActivityEvent } from "@/lib/api/activity.gen";

/** The segments of the Activity tab. */
export const ACTIVITY_MODES = [
  { value: "connections", label: "Connections" },
  { value: "dns", label: "DNS" },
  { value: "events", label: "Events" },
] as const;

export type ActivityMode = (typeof ACTIVITY_MODES)[number]["value"];

const EVENT_KINDS: Record<ActivityMode, readonly string[]> = {
  connections: [],
  dns: ["dns"],
  events: ["vpn", "route_added", "route_removed", "refused"],
};

/** Whether a mode that lists activity events includes `kind`. */
export function modeIncludes(mode: ActivityMode, kind: string): boolean {
  return EVENT_KINDS[mode].includes(kind);
}

export const addressesOf = (event: ActivityEvent): Address[] => event.addresses ?? [];
export const isIPv6 = (address: Address): boolean => address.ip.includes(":");
export const isVpnAddress = (address: Address): boolean => address.verdict === "vpn";

/** The managed VPN the event concerns: the one the helper named, or the VPN a VPN event is about. */
export function concernedVpn(event: ActivityEvent): string | undefined {
  return event.vpn || (event.kind === "vpn" ? event.name || undefined : undefined);
}

/**
 * A listed name's AAAA answer. RouteWise routes IPv4 only, so these addresses
 * never enter a tunnel; whether they go anywhere depends on the network.
 */
export function isUnroutedIPv6Answer(event: ActivityEvent): boolean {
  const addresses = addressesOf(event);
  return (
    event.kind === "dns" &&
    event.list != null &&
    addresses.length > 0 &&
    addresses.every((a) => isIPv6(a) && !isVpnAddress(a))
  );
}

/** A helper timestamp (RFC 3339, nanoseconds) as a Date, or undefined when unreadable. */
export function parseTime(time: string): Date | undefined {
  const ms = Date.parse(time);
  return Number.isNaN(ms) ? undefined : new Date(ms);
}
