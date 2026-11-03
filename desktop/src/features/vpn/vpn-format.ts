import type { ProfileInfo, ProfileStats, StatusResult } from "@/lib/api/types.gen";

export type ProxyKind = "socks5" | "http";
export type ProfileKind = "wireguard" | "outline" | ProxyKind | "unknown";
export type ProfileState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "error"
  | "needsCredentials"
  | "unknown";

const KIND_TITLES: Record<ProfileKind, string> = {
  wireguard: "WireGuard",
  outline: "Outline",
  socks5: "SOCKS5",
  http: "HTTP proxy",
  unknown: "VPN",
};
const STATE_LABELS: Record<ProfileState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  error: "Error",
  needsCredentials: "Needs credentials",
  unknown: "Unknown",
};

/** The kind of a profile; one a newer helper adds reads as `unknown`. */
export function profileKind(profile: Pick<ProfileInfo, "kind">): ProfileKind {
  return profile.kind === "wireguard" ||
    profile.kind === "outline" ||
    profile.kind === "socks5" ||
    profile.kind === "http"
    ? profile.kind
    : "unknown";
}

export function kindTitle(kind: ProfileKind): string {
  return KIND_TITLES[kind];
}

/** The state of a profile; one a newer helper adds reads as `unknown`. */
export function profileState(profile: Pick<ProfileInfo, "state">): ProfileState {
  return profile.state in STATE_LABELS ? (profile.state as ProfileState) : "unknown";
}

export function stateLabel(state: ProfileState): string {
  return STATE_LABELS[state];
}

/** Up or coming up: a connect toggle reads on. */
export function isActive(state: ProfileState): boolean {
  return state === "connected" || state === "connecting";
}

/** Connected, coming up, or failing and retrying: the helper is running it. */
export function isRunning(state: ProfileState): boolean {
  return isActive(state) || state === "error";
}

/** A VPN client or profile: its name, or its id when it has none. */
export function displayName(name: string, id: string): string {
  return name === "" ? id : name;
}

/** The id a built-in profile has in domain lists and in the VPN allowlist. */
export function profileClientId(profile: Pick<ProfileInfo, "kind" | "id">): string {
  return `routewise-${profileKind(profile)}:${profile.id}`;
}

/** Whether a client id names a built-in profile rather than a VPN app's path. */
export function isBuiltInClientId(clientId: string): boolean {
  const colon = clientId.indexOf(":");
  return clientId.startsWith("routewise-") && colon >= 0 && colon < clientId.length - 1;
}

/** Whether the VPN app or profile with `clientId` has a tunnel up in `status`. */
export function isClientConnected(clientId: string, status: StatusResult | undefined): boolean {
  if (!status?.vpnConnected) return false;
  const tunnels = status.tunnels ?? [];
  if (tunnels.some((t) => t.client.id === clientId)) return true;
  return tunnels.length === 0 && status.vpnClient?.id === clientId;
}

export function routeLabel(count: number): string {
  return count === 1 ? "1 route" : `${count} routes`;
}

/** "Connected via utun7 · 4 routes", "Not working — retrying", and so on. */
export function stateText(profile: ProfileInfo, routeCount?: number): string {
  const state = profileState(profile);
  if (state === "connected") {
    let text = "Connected";
    if (profile.interface) text += ` via ${profile.interface}`;
    if (routeCount !== undefined) text += ` · ${routeLabel(routeCount)}`;
    return text;
  }
  if (state === "error") return "Not working — retrying";
  return stateLabel(state);
}

/** 1024-based, one decimal from KB up: "0 B", "1023 B", "1.5 KB", "2.0 MB". */
export function formatBytes(count: number): string {
  if (count < 1024) return `${count} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let value = count / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** "5 s ago", "3 min ago", "2 h ago", "4 d ago"; "never" when there is no handshake. */
export function formatAgo(seconds: number | undefined): string {
  if (seconds === undefined) return "never";
  const s = Math.max(0, seconds);
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

/** Epoch milliseconds are above this; anything below is read as an age. */
const EPOCH_THRESHOLD_MS = 100_000_000_000;

/**
 * Age of the last handshake in seconds. The helper's value is read as epoch
 * milliseconds, or as an age in milliseconds when too small to be a date.
 * Undefined for none (absent or zero).
 */
export function handshakeAge(lastHandshakeMs: number | undefined, nowMs: number = Date.now()): number | undefined {
  if (!lastHandshakeMs || lastHandshakeMs <= 0) return undefined;
  if (lastHandshakeMs >= EPOCH_THRESHOLD_MS) return Math.max(0, Math.floor((nowMs - lastHandshakeMs) / 1000));
  return Math.floor(lastHandshakeMs / 1000);
}

/** "↓1.5 MB ↑200 B", plus handshake and flow counts when reported. */
export function statsLine(stats: ProfileStats, kind: ProfileKind, nowMs: number = Date.now()): string {
  const parts = [`↓${formatBytes(stats.rxBytes ?? 0)} ↑${formatBytes(stats.txBytes ?? 0)}`];
  const age = handshakeAge(stats.lastHandshakeMs, nowMs);
  if (kind === "wireguard" && age !== undefined) {
    parts.push(`handshake ${formatAgo(age)}`);
  } else if (kind === "wireguard") {
    parts.push("handshake never");
  }
  const { tcpFlows, udpFlows } = stats;
  if (tcpFlows !== undefined && udpFlows !== undefined) parts.push(`TCP ${tcpFlows} / UDP ${udpFlows}`);
  else if (tcpFlows !== undefined) parts.push(`TCP ${tcpFlows}`);
  else if (udpFlows !== undefined) parts.push(`UDP ${udpFlows}`);
  return parts.join(" · ");
}

const KEY_PREFIXES = ["ss://", "ssconf://"];

/** The access key as it is sent: without surrounding whitespace. */
export function normalizeAccessKey(key: string): string {
  return key.trim();
}

/** Client-side check of an Outline access key; the helper parses it for real. */
export function accessKeyProblem(key: string): string | null {
  const trimmed = normalizeAccessKey(key);
  if (trimmed === "") return "Enter an access key.";
  const prefix = KEY_PREFIXES.find((p) => trimmed.toLowerCase().startsWith(p));
  if (!prefix) return "The key must start with ss:// or ssconf://.";
  return trimmed.length > prefix.length ? null : "The key is incomplete.";
}

export interface ProxyFields {
  host: string;
  port: string;
  username: string;
  password: string;
}

/** Client-side check of a proxy; the helper parses the address for real. */
export function proxyProblem({ host, port, username, password }: ProxyFields): string | null {
  if (host.trim() === "") return "Enter the proxy's host.";
  if (/[\s/@?#]/.test(host.trim())) return "Enter only the host, such as 127.0.0.1 or proxy.example.com.";
  const portNumber = Number(port.trim());
  if (!/^\d+$/.test(port.trim()) || portNumber < 1 || portNumber > 65535) return "The port must be between 1 and 65535.";
  if ((username === "") !== (password === "")) return "Enter both a username and a password, or neither.";
  return null;
}

/** The address the helper stores, with the username and password percent-encoded. */
export function proxyAddress(kind: ProxyKind, { host, port, username, password }: ProxyFields): string {
  const trimmed = host.trim().replace(/^\[|\]$/g, "");
  const name = trimmed.includes(":") ? `[${trimmed}]` : trimmed;
  const login = username === "" ? "" : `${encodeURIComponent(username)}:${encodeURIComponent(password)}@`;
  return `${kind}://${login}${name}:${port.trim()}`;
}

/**
 * Whether a host is reachable only from this machine or its network. A name counts as
 * public unless it is localhost, since where it leads is not known here.
 */
export function isLocalHost(host: string): boolean {
  const name = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (name === "localhost" || name === "::1") return true;
  const octets = name.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return false;
  const [a, b] = octets;
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}
