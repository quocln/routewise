# DNS

## Wildcards

A wildcard has no addresses to resolve ahead of time, so RouteWise routes each name as it is looked up:

1. While a VPN with a wildcard is connected, RouteWise sends that suffix's lookups to its local forwarder, using `/etc/resolver/<suffix>` files on macOS,
   routing domains on Linux and NRPT rules on Windows.
2. The forwarder asks upstream.
3. It adds a route for the answer **before replying**, so the app's first connection already goes through the tunnel.

Learned routes last for the longer of the record's TTL and 30 minutes, are refreshed by each lookup, and are capped at 2000 addresses. RouteWise never overwrites a
resolver file it does not own, and removes its own when the VPN disconnects and at start.

An app with its own DNS-over-HTTPS, such as Chrome's Secure DNS, skips all of this, so wildcard names it looks up are not routed.

## Which server is asked

The forwarder asks the VPN's DNS servers first when `dns.use_vpn_dns` is on, then `dns.servers`. Within each group it starts with the first server, and also asks the next if
there is no reply after 200 ms, or at once on SERVFAIL or REFUSED. The first positive answer wins.

This hedging means a dead first server costs 200 ms per query rather than a timeout. It gains nothing in a group of one, where a dead server still means waiting. There is no
memory of which server is dead: [decision 0003](../decisions/0003-hedged-dns-without-server-memory.md) says why.

## The VPN's DNS servers

- A VPN app's DNS servers are always routed through its tunnel. Once the default route leaves the tunnel, every lookup it serves would otherwise fail.
- A built-in VPN's DNS servers are routed only while `dns.use_vpn_dns` is on. One that is also a system resolver, in `dns.servers`, or used by another profile is refused.
- `dns.use_vpn_dns` only decides who RouteWise's own resolver asks first.

Server selection prefers servers bound to the tunnel in `scutil --dns`. When none are bound, as with `wg-quick`, it guesses: private servers outside every directly connected subnet.
A guess is replaced once bound servers appear.

## The system resolver

RouteWise does not change it. A built-in VPN's DNS never becomes the system's. So with a [default VPN](../how-to/set-default-vpn.md) and a resolver on your LAN, the LAN still sees
the names you look up.
