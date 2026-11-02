import type { RouteEntry } from "@/lib/api/types.gen";
import type { ListNames } from "@/features/activity/list-names";
import { parseTime } from "@/features/activity/activity-event";

/** One tunnel the routes go through, for the summary chips and the filter. */
export interface Via {
  id: string;
  clientId?: string;
  name?: string;
  interface?: string;
  count: number;
}

/** Identifies the tunnel a route goes through: its client id, or its interface for a route a retired tunnel left behind. */
export function viaKey(route: RouteEntry): string {
  return route.clientId ? route.clientId : (route.interface ?? "");
}

/** The tunnels `routes` go through, each once, in the order they first appear. */
export function viasOf(routes: readonly RouteEntry[]): Via[] {
  const vias = new Map<string, Via>();
  for (const route of routes) {
    const key = viaKey(route);
    const via = vias.get(key);
    if (via) via.count += 1;
    else vias.set(key, { id: key, clientId: route.clientId, name: route.vpn, interface: route.interface, count: 1 });
  }
  return [...vias.values()];
}

/** Routes through `via` (undefined for all) whose IP, gateway, domain, matched entry, VPN, or interface contains `search`. */
export function filterRoutes(routes: readonly RouteEntry[], search: string, via: string | undefined): RouteEntry[] {
  const query = search.trim().toLowerCase();
  return routes.filter((route) => {
    if (via !== undefined && viaKey(route) !== via) return false;
    if (query === "") return true;
    return [route.ip, route.gateway, route.domain, route.rule, route.vpn, route.interface].some((field) =>
      field?.toLowerCase().includes(query),
    );
  });
}

/** The name of the VPN a route went through: its list's title while that list exists, else the name recorded with the route. */
export function vpnTitle(names: ListNames, clientId: string | undefined, recordedName: string | undefined): string | undefined {
  if (clientId && names.items.some((item) => item.id === clientId)) return names.title(clientId);
  return recordedName ? recordedName : undefined;
}

const VPN_INTERFACE_PREFIXES = ["utun", "tun", "ppp", "ipsec"];
const PRIVATE_GATEWAY_PREFIXES = ["10.", "192.168.", "172.", "100."];

/** Whether the route goes through a tunnel: by its interface, or by its gateway for a helper that sends none. */
export function isVpnRoute(route: Pick<RouteEntry, "interface" | "gateway">): boolean {
  const iface = route.interface;
  if (iface && iface !== "local") return VPN_INTERFACE_PREFIXES.some((prefix) => iface.startsWith(prefix));
  return PRIVATE_GATEWAY_PREFIXES.some((prefix) => route.gateway.startsWith(prefix));
}

/** "1 route" or "N routes". */
export const routeLabel = (count: number): string => (count === 1 ? "1 route" : `${count} routes`);

/** A short local time, or the text itself when it is not a timestamp. */
export function formatAddedAt(addedAt: string): string {
  const date = parseTime(addedAt);
  return date ? date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : addedAt;
}
