# What RouteWise can and cannot see

RouteWise decides per destination address, not per connection or per app. Per-app routing would need a NetworkExtension, which it deliberately does not use.

## Passive capture

The helper reads copies of packet headers on each interface and changes nothing. It keeps three kinds of packet: DNS answers, TCP connection starts, and QUIC connection starts.

Becoming the system resolver would see more, but would rewrite every network service's DNS, fight what VPNs push, and risk breaking all lookups. If capture cannot start, the helper logs a
warning and keeps routing. Those views are then empty.

## What each view cannot see

| View | Cannot see |
|---|---|
| DNS | Answers from the system's cache, DNS over TCP, DNS-over-HTTPS, DNS-over-TLS |
| Connections | Protocols other than TCP and QUIC on port 443, or connections inside an app's own tunnel. The domain is blank if the address was never resolved while RouteWise watched |
| Host check | Nothing hidden, but it answers for now, by asking the kernel |

## Verdicts

A connection's verdict comes from the interface it was captured on: a managed tunnel is `vpn`, a tunnel RouteWise does not manage is `other`, and anything else is `direct`. That makes it what
happened, not what was intended.

## Privacy

The history lists every host this computer contacted, and never packet contents. Reading it needs root or the console user. [Turn it off](../how-to/inspect-traffic.md#turn-the-history-off) if that
does not suit your machine.

The log file gets activity events at `info`, and DNS lookups only at `debug`.

## Limits

The activity log keeps the latest 2000 events in memory. With history on they are also stored for the retention period and survive a restart. Writes to disk are batched on their own connection,
so capture never waits on the database.
