# How routing decisions are made

## Inverted split tunnel

A full-tunnel VPN installs catch-all routes that send everything into its tunnel. RouteWise takes those away, so traffic goes direct, then adds a
route for each listed destination. The VPN stays connected: its client keeps its own route to its server.

The VPN client may put its routes back, for example after waking from sleep. The control loop checks and removes them again, every 2 seconds just
after connecting and every 10 seconds after that.

Addresses are what the kernel routes, so RouteWise resolves names to addresses. Exact names are resolved up front and again every
`dns.cache_ttl`. Wildcards [are routed as they are looked up](dns.md#wildcards).

`routing.mode: additive` leaves a VPN's catch-all routes in place and only adds routes. It exists for coexisting with other tools.

## Who owns a destination

1. A name in a VPN's list goes through that VPN, and beats **Any VPN**.
2. If that VPN is down or unhealthy, the name goes direct and never through another VPN, because a destination reachable through one VPN must not
   leak into another. The exception is a default VPN you chose yourself, below.
3. **Any VPN** entries use the highest-priority healthy VPN app. A built-in VPN never carries them.
4. If several VPNs list a name, the highest priority owns it.
5. If two VPNs want one address, as two names on one CDN might, the higher priority takes it and the other records a refusal.

Priority is the order under **VPN apps**.

## Why VPNs must be allowed

RouteWise rewrites routes. Doing that to a VPN you never chose, or to a corporate client with a kill switch, should not be the default. So a detected VPN
is left alone until you choose **Manage this VPN**.

A VPN is identified by the program holding its tunnel, not by its interface name, which macOS reuses.

## Built-in VPNs

The helper creates and owns the tunnel, so there is no NetworkExtension, and several can run with each other and with a NetworkExtension VPN. They install no
catch-all routes, so nothing is taken away. A new tunnel holds its list for up to 10 seconds while it proves itself, so a connection opened then waits for it
rather than going direct for its whole life.

## The default VPN

The chosen tunnel gets four `/2` routes. Every list entry is `/8` or longer, so it wins and keeps its own tunnel. The default route stays on the LAN, so "direct"
is just removing those four routes. A listed name whose VPN is down has no route of its own and falls into them, which needs no extra rule.

Why not the `/1` pair a VPN uses: the table holds one route per destination. Holding `0/1` and `128/1` would make the next VPN's own route fail, and that pair is
how RouteWise detects a VPN at all, so it would never be managed. See [decision 0002](../decisions/0002-default-vpn-uses-slash-2-routes.md).

Two things go in first, because a mistake here cuts off the whole machine:

- A route through the LAN to each built-in VPN's server, so its transport cannot enter a tunnel. VPN apps install their own.
- A reject route for global IPv6, unless it is allowed, because RouteWise routes IPv4 only.

A built-in tunnel takes the role only once proven and with a known server. Any failure that makes the role unsafe sends traffic direct, and it tries again within
5 seconds. What is reported comes from what is really held.

## IPv6

RouteWise routes IPv4 only, and a browser prefers an IPv6 address when it has one, so a listed name could leave around its VPN. Unless `routing.allow_ipv6` is on, each
IPv6 address in a DNS answer for a listed name gets a reject route. A reject fails `connect()` at once, so Happy Eyeballs moves to IPv4. A blackhole would hang until a
timeout. Only global unicast addresses are blocked, for at least 5 minutes and at most 1024 at a time.

## After a crash

Each route change that could outlive the helper is journaled first. The next start undoes what the journals name.
