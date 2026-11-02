# 0002 Default VPN Uses /2 Routes

Date: 2026-11-02

## Status

Accepted

## Context

The default VPN must carry whatever no list claims, while list routes keep their own tunnels and direct stays one step away. The obvious shape is the `0.0.0.0/1` and `128.0.0.0/1` pair full-tunnel VPNs install.

Review found the problem. The routing table holds one route per destination. Holding the pair makes the next VPN client's own `route add` fail, and that pair is how the monitor detects a client. So that client is never managed, and its domains
go through the wrong VPN.

## Decision

The role uses four `/2` routes. They outrank a client's `/1` pair, which stays free. List entries stop at `/8`, so every list route still wins. The default route stays on the LAN.

## Alternatives Considered

1. The `/1` pair: the problem above.
2. Moving the default route into the tunnel: "direct" would then need restoring it, and a helper crash would leave the machine routed through the tunnel.

## Consequences

A crash leaves routes on a VPN app's tunnel that nothing else would remove, so the role journals them. On macOS, a socket bound to the primary interface gets `ENETUNREACH` for covered addresses, because the kernel finds the route through the tunnel and the primary interface
has no scoped default. Adding one did not take effect when tried, so this is documented rather than fixed.
