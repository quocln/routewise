import { describe, expect, it } from "vitest";
import type { ProfileInfo, StatusResult } from "@/lib/api/types.gen";
import {
  accessKeyProblem,
  displayName,
  formatAgo,
  formatBytes,
  handshakeAge,
  isBuiltInClientId,
  isClientConnected,
  isLocalHost,
  profileClientId,
  profileKind,
  profileState,
  proxyAddress,
  proxyProblem,
  stateText,
  statsLine,
} from "./vpn-format";

const profile = (over: Partial<ProfileInfo> = {}): ProfileInfo => ({
  id: "p1",
  kind: "wireguard",
  name: "Work",
  autoConnect: false,
  dns: [],
  state: "disconnected",
  ...over,
});

describe("formatBytes", () => {
  it("uses 1024-based units with one decimal from KB up", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(2 * 1024 * 1024)).toBe("2.0 MB");
  });
});

describe("formatAgo and handshakeAge", () => {
  it("names the largest whole unit", () => {
    expect(formatAgo(undefined)).toBe("never");
    expect(formatAgo(5)).toBe("5 s ago");
    expect(formatAgo(180)).toBe("3 min ago");
    expect(formatAgo(7200)).toBe("2 h ago");
    expect(formatAgo(4 * 86_400)).toBe("4 d ago");
  });

  it("reads an epoch time as a date and a small value as an age", () => {
    const now = 1_800_000_000_000;
    expect(handshakeAge(now - 12_000, now)).toBe(12);
    expect(handshakeAge(45_000, now)).toBe(45);
    expect(handshakeAge(0, now)).toBeUndefined();
    expect(handshakeAge(undefined, now)).toBeUndefined();
  });
});

describe("statsLine", () => {
  const now = 1_800_000_000_000;
  it("shows traffic and the WireGuard handshake", () => {
    const stats = { rxBytes: 1536, txBytes: 200, lastHandshakeMs: now - 5_000 };
    expect(statsLine(stats, "wireguard", now)).toBe("↓1.5 KB ↑200 B · handshake 5 s ago");
  });

  it("says a WireGuard tunnel never shook hands, and shows Outline flows instead", () => {
    expect(statsLine({ rxBytes: 0, txBytes: 0 }, "wireguard", now)).toContain("handshake never");
    const outline = statsLine({ rxBytes: 0, txBytes: 0, tcpFlows: 3, udpFlows: 1 }, "outline", now);
    expect(outline).toBe("↓0 B ↑0 B · TCP 3 / UDP 1");
  });
});

describe("profile helpers", () => {
  it("reads unknown kinds and states generically", () => {
    expect(profileKind({ kind: "ipsec" })).toBe("unknown");
    expect(profileState({ state: "hibernating" })).toBe("unknown");
    expect(profileState({ state: "needsCredentials" })).toBe("needsCredentials");
  });

  it("names a profile by its id when it has no name", () => {
    expect(displayName("", "p1")).toBe("p1");
    expect(displayName("Work", "p1")).toBe("Work");
  });

  it("derives the client id used by domain lists and the allowlist", () => {
    expect(profileClientId(profile())).toBe("routewise-wireguard:p1");
    expect(isBuiltInClientId("routewise-outline:abc")).toBe(true);
    expect(isBuiltInClientId("routewise-outline:")).toBe(false);
    expect(isBuiltInClientId("/Applications/AWS VPN Client.app")).toBe(false);
  });

  it("describes the state of a profile", () => {
    expect(stateText(profile({ state: "connected", interface: "utun7" }), 4)).toBe("Connected via utun7 · 4 routes");
    expect(stateText(profile({ state: "connected" }), 1)).toBe("Connected · 1 route");
    expect(stateText(profile({ state: "error" }))).toBe("Not working — retrying");
    expect(stateText(profile({ state: "needsCredentials" }))).toBe("Needs credentials");
  });
});

describe("isClientConnected", () => {
  const base: StatusResult = { running: true, vpnConnected: true, routeCount: 1 };
  it("matches a tunnel by client id", () => {
    const status = { ...base, tunnels: [{ interface: "utun4", client: { id: "/a", name: "A" }, routeCount: 1 }] };
    expect(isClientConnected("/a", status)).toBe(true);
    expect(isClientConnected("/b", status)).toBe(false);
  });

  it("falls back to vpnClient for a helper that reports no tunnels", () => {
    expect(isClientConnected("/a", { ...base, vpnClient: { id: "/a", name: "A" } })).toBe(true);
  });

  it("is false while no VPN is up or the status is missing", () => {
    expect(isClientConnected("/a", { ...base, vpnConnected: false })).toBe(false);
    expect(isClientConnected("/a", undefined)).toBe(false);
  });
});

describe("accessKeyProblem", () => {
  it("accepts ss:// and ssconf:// keys in any case, with whitespace around", () => {
    expect(accessKeyProblem("  ss://fake-body  ")).toBeNull();
    expect(accessKeyProblem("SSCONF://example.invalid/fake")).toBeNull();
  });

  it("explains what is wrong", () => {
    expect(accessKeyProblem("   ")).toBe("Enter an access key.");
    expect(accessKeyProblem("https://example.invalid")).toBe("The key must start with ss:// or ssconf://.");
    expect(accessKeyProblem("ss://")).toBe("The key is incomplete.");
  });
});

describe("proxies", () => {
  const fields = { host: "proxy.example.com", port: "1080", username: "", password: "" };

  it("knows the kind", () => {
    expect(profileKind({ kind: "socks5" })).toBe("socks5");
    expect(profileKind({ kind: "http" })).toBe("http");
  });

  it("builds the address", () => {
    expect(proxyAddress("socks5", fields)).toBe("socks5://proxy.example.com:1080");
    expect(proxyAddress("socks5", { ...fields, host: " ::1 " })).toBe("socks5://[::1]:1080");
    expect(proxyAddress("socks5", { ...fields, host: "[::1]" })).toBe("socks5://[::1]:1080");
    expect(proxyAddress("socks5", { ...fields, username: "a b", password: "c/d" })).toBe(
      "socks5://a%20b:c%2Fd@proxy.example.com:1080",
    );
  });

  it("builds an HTTP proxy's address", () => {
    expect(proxyAddress("http", { ...fields, port: "8080" })).toBe("http://proxy.example.com:8080");
  });

  it("finds what the helper would refuse", () => {
    expect(proxyProblem(fields)).toBeNull();
    expect(proxyProblem({ ...fields, host: " " })).toMatch(/host/);
    expect(proxyProblem({ ...fields, host: "user@host" })).toMatch(/only the host/);
    expect(proxyProblem({ ...fields, port: "0" })).toMatch(/port/);
    expect(proxyProblem({ ...fields, port: "65536" })).toMatch(/port/);
    expect(proxyProblem({ ...fields, port: "1e3" })).toMatch(/port/);
    expect(proxyProblem({ ...fields, username: "me" })).toMatch(/both/);
    expect(proxyProblem({ ...fields, password: "pw" })).toMatch(/both/);
  });

  it("tells a local host from a public one", () => {
    for (const host of ["localhost", "127.0.0.1", "::1", "[::1]", "10.1.2.3", "172.16.0.1", "172.31.0.1", "192.168.1.1"]) {
      expect(isLocalHost(host)).toBe(true);
    }
    for (const host of ["203.0.113.9", "172.32.0.1", "8.8.8.8", "proxy.example.com", "10.0.0", "999.1.1.1"]) {
      expect(isLocalHost(host)).toBe(false);
    }
  });
});
