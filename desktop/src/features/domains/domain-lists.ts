import type { ProfileInfo, Settings, StatusResult, VPNClient } from "@/lib/api/types.gen";

/** The client id of the "Any VPN" list. */
export const ANY_VPN_ID = "";

export type ListGroup = "any" | "builtIn" | "app";
/** Colour family of a list's state dot. */
export type StateTone = "green" | "yellow" | "red" | "orange" | "muted";
export type ListIcon = "globe" | "wireguard" | "outline" | "network" | "app";

/** One list in the Domains sidebar: "Any VPN", a built-in profile, or a VPN app. */
export interface DomainListItem {
  id: string;
  group: ListGroup;
  title: string;
  icon: ListIcon;
  stateTone: StateTone;
  stateLabel: string;
  /** Whether the list's entries route through a tunnel right now. */
  isRouting: boolean;
}

/** The profile id inside a built-in client id ("routewise-<kind>:<id>"), or undefined for anything else. */
export function profileIdFromClientId(vpnId: string): string | undefined {
  const colon = vpnId.indexOf(":");
  if (!vpnId.startsWith("routewise-") || colon < 0) return undefined;
  const id = vpnId.slice(colon + 1);
  return id === "" ? undefined : id;
}

/** Whether `vpnId` names a built-in WireGuard or Outline profile rather than a VPN app's executable path. */
export function isBuiltInClientId(vpnId: string): boolean {
  return profileIdFromClientId(vpnId) !== undefined;
}

/** The client id the helper keys a built-in profile's domain list by. */
export function profileClientId(profile: Pick<ProfileInfo, "kind" | "id">): string {
  return `routewise-${profile.kind}:${profile.id}`;
}

/**
 * Whether the VPN with `vpnId` is up. Matches tunnels by client id and falls
 * back to `vpnClient` for a helper that does not report tunnels. "Any VPN" is
 * up when any managed tunnel that is not a built-in one is.
 */
export function isVpnConnected(vpnId: string, status: StatusResult | undefined): boolean {
  if (!status?.vpnConnected) return false;
  const tunnels = status.tunnels ?? [];
  if (vpnId === ANY_VPN_ID) {
    return tunnels.length === 0 || tunnels.some((t) => !isBuiltInClientId(t.client.id));
  }
  if (tunnels.some((t) => t.client.id === vpnId)) return true;
  return tunnels.length === 0 && status.vpnClient?.id === vpnId;
}

/** Name of the VPN "Any VPN" currently routes through: the highest-priority connected detected one. */
export function activeVpnName(status: StatusResult | undefined): string | undefined {
  if (!status?.vpnConnected) return undefined;
  const external = status.tunnels?.find((t) => !isBuiltInClientId(t.client.id));
  const name = external?.client.name ?? status.vpnClient?.name;
  return name ? name : "VPN";
}

/** A VPN client or profile: its name, or its id when it has none. */
export function clientDisplayName(client: VPNClient): string {
  return client.name === "" ? client.id : client.name;
}

function profileTone(state: string): StateTone {
  switch (state) {
    case "connected":
      return "green";
    case "connecting":
      return "yellow";
    case "error":
      return "red";
    case "needsCredentials":
      return "orange";
    default:
      return "muted";
  }
}

const PROFILE_STATE_LABELS: Record<string, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  error: "Error",
  needsCredentials: "Needs credentials",
};

/** A state a newer helper adds reads as "Unknown" and as not connected. */
function profileStateLabel(state: string): string {
  return PROFILE_STATE_LABELS[state] ?? "Unknown";
}

function profileIcon(kind: string): ListIcon {
  if (kind === "wireguard") return "wireguard";
  if (kind === "outline") return "outline";
  return "network";
}

/**
 * Builds the sidebar from the allowed clients, the built-in profiles, and the
 * helper status. Built-in profiles take their state from the profile list,
 * which knows "connecting" and "error"; VPN apps from the tunnels.
 */
export function buildListItems(
  clients: readonly VPNClient[],
  profiles: readonly ProfileInfo[],
  status: StatusResult | undefined,
): DomainListItem[] {
  const anyUp = isVpnConnected(ANY_VPN_ID, status);
  const items: DomainListItem[] = [
    {
      id: ANY_VPN_ID,
      group: "any",
      title: "Any VPN",
      icon: "globe",
      stateTone: anyUp ? "green" : "muted",
      stateLabel: anyUp ? `via ${activeVpnName(status) ?? "VPN"}` : "No VPN app connected",
      isRouting: anyUp,
    },
  ];
  for (const client of clients) {
    const profileId = profileIdFromClientId(client.id);
    if (profileId === undefined) continue;
    const profile = profiles.find((p) => p.id === profileId);
    const state = profile?.state ?? "unknown";
    items.push({
      id: client.id,
      group: "builtIn",
      title: profile?.name ? profile.name : clientDisplayName(client),
      icon: profile ? profileIcon(profile.kind) : "wireguard",
      stateTone: profileTone(state),
      stateLabel: profile ? profileStateLabel(state) : "",
      isRouting: state === "connected",
    });
  }
  for (const client of clients) {
    if (isBuiltInClientId(client.id)) continue;
    const up = isVpnConnected(client.id, status);
    items.push({
      id: client.id,
      group: "app",
      title: clientDisplayName(client),
      icon: "app",
      stateTone: up ? "green" : "muted",
      stateLabel: up ? "Connected" : "Not connected",
      isRouting: up,
    });
  }
  return items;
}

/** The explanatory line under a list's title. */
export function listCaption(item: DomainListItem, status: StatusResult | undefined): string {
  const scope = scopeCaption(item.id, status);
  switch (item.group) {
    case "any":
      return `${scope}. Built-in VPNs never carry this list.`;
    case "builtIn":
      return item.isRouting
        ? `Connected — these entries route through ${item.title}.`
        : `Not routing — these entries go direct until ${item.title} is connected and working.`;
    case "app":
      return scope;
  }
}

function scopeCaption(vpnId: string, status: StatusResult | undefined): string {
  if (!isVpnConnected(vpnId, status)) return "Not connected — these domains go direct until it connects";
  if (vpnId === ANY_VPN_ID) {
    return `Routes through the highest-priority connected VPN (${activeVpnName(status) ?? "VPN"} right now)`;
  }
  return "Connected — these domains route through this VPN";
}

/** Every list a count is shown for: each list, plus profiles whose client is not allowed yet. */
export function countListIds(items: readonly DomainListItem[], profiles: readonly ProfileInfo[]): string[] {
  return Array.from(new Set([...items.map((i) => i.id), ...profiles.map(profileClientId)])).sort();
}

/** The allowed clients out of settings, empty before they load. */
export function allowedClients(settings: Settings | undefined): VPNClient[] {
  return settings?.allowedVpnClients ?? [];
}
