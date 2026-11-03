# Platforms

## How each platform does it

| | macOS | Linux (systemd, systemd-resolved) | Windows 10/11 |
|---|---|---|---|
| Service | launchd | `routewise.service` | Service `RouteWise` |
| Who may change routing | Root or the console user | Root or the seat0 active user | Elevated admins or the active console user |
| Route table | Routing socket; `/sbin/route` for the default route and as a fallback | netlink | IP Helper |
| VPN detection | `utun` with a default or `0/1` and `128/1` | tun, tap and wireguard links, routes and policy rules | Adapter driver |
| Split DNS | `/etc/resolver/<suffix>` | Routing domains on an `rw-dns` link | NRPT rules |
| Traffic capture | BPF | `AF_PACKET` | Raw socket |
| Built-in tunnels | `utun` | `rwtunN` | Wintun |
| DNS forwarder | `127.0.0.1:53053` | `127.0.0.1:53053` | `127.0.0.1:53` |

## What has been tested where

Unit tests and CI cover all three. This table is what has also run for real, and it is the one place that says so.

| Area | macOS | Linux | Windows |
|---|---|---|---|
| Install and service | Yes | In a VM | Not yet |
| Built-in WireGuard and Outline | Yes | WireGuard, in a VM | Not yet |
| Built-in SOCKS5, against a real proxy | Yes, Dante on this machine; a proxy elsewhere not yet | Not yet | Not yet |
| Built-in HTTP proxy, against a real proxy | Yes, tinyproxy on this machine; a proxy elsewhere not yet | Not yet | Not yet |
| Wildcard routing and DNS clearing | Yes | Not recorded | Not yet |
| VPN apps, as allowed clients | Not recently | OpenVPN and wg-quick, in a VM | Not yet |
| Scan for VPN apps and Add app, against a helper | Scan, with no VPN app installed; Add app not yet | Not yet | Not yet |
| Default VPN: move, fallback, direct, return | Yes, with built-in tunnels | Not yet | Not yet |
| Default VPN with a VPN app | Not yet | Not yet | Not yet |
| Default VPN exceptions | Yes, with Outline; a helper crash while they are in place not yet | Not yet | Not yet |
| Default VPN across a change of network | Not yet | Not yet | Not yet |
| Dashboard and tray figures in the installed app | Not confirmed | Not yet | Not yet |
| Route changes through the routing socket | Not confirmed | Not applicable | Not applicable |

Update this table when something is proven.
