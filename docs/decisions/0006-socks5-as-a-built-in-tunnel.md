# 0006 SOCKS5 As A Built-In Tunnel

Date: 2026-11-03

## Status

Accepted

## Context

Some people have a SOCKS5 proxy and no VPN: one they bought, or `ssh -D`. RouteWise routes through interfaces, and a proxy has none. Outline's tunnel already turns a `utun` into outgoing streams through a dialer, so it can carry any protocol that dials.

## Decision

SOCKS5 is a built-in tunnel kind, sharing Outline's tunnel through `StartWithDialer`. So lists, the default VPN and exceptions work unchanged. The secret is a `socks5://` URL in the existing `accessKey` field, and it can hold a password, so it follows every rule an Outline key does.

A flow to port 53 goes over TCP instead of the proxy's UDP relay, because many proxies have none and a machine whose lookups fail is broken in a way other UDP failing is not. A health check counts a proxy as up when it answers and accepts the login, even if it reports the check's target unreachable or forbidden. A proxy on this machine has no known server, so it cannot be the default VPN: what it connects onward to would enter the tunnel it serves.

## Alternatives Considered

1. SOCKS4 and SOCKS4a: no password, no UDP, no IPv6, and little use left.
2. RouteWise as a local SOCKS5 server that apps point at: per-app setup, which is what routing in the kernel exists to avoid.
3. A health check that needs the proxy to reach the Internet: a company proxy that reaches only company addresses would never be proven, and an unproven tunnel sends its list direct, around the proxy.

## Consequences

SOCKS5 encrypts nothing, which the app says whenever a proxy is added. A proxy that has lost its own connection can show as connected, and its traffic then fails rather than leaks. The SDK's client waits for a proxy's replies with no limit, and offers one authentication method at a time, so `proxyclient` bounds the handshake by the caller's context and retries without credentials when a proxy refuses them. The retry depends on the text of an SDK error, which a test holds in place.
