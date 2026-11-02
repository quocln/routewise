# List entries

`config.ParseEntry` validates entries for the app, the CLI, the RPC and the config file alike.

## Domains and wildcards

An exact name, or a name with one `*` in its first label and at least two labels after it. A wildcard matches exactly one label.

| Pattern | Matches | Does not match |
|---|---|---|
| `example.com` | `example.com` | `sub.example.com` |
| `*.example.com` | `api.example.com` | `example.com`, `a.b.example.com` |
| `qa*.staging.example.com` | `qa1.staging.example.com` | `prod.staging.example.com` |

Refused: `*.com` (too few labels), `api.*.example.com` (not the first label), `*a*.example.com` (more than one `*`).

## IPv4 addresses and CIDRs

Routed as given and never resolved. `x/32` is stored as the plain address. A CIDR with host bits is stored as its network, so
`10.20.5.1/16` becomes `10.20.0.0/16`.

## Refused when added

- IPv6.
- A CIDR shorter than `/8`.
- Anything that is or overlaps `0.0.0.0/8`, loopback, link-local (`169.254.0.0/16`), or multicast and reserved (`224.0.0.0/3`).

## Refused when routes sync

These depend on the network you are on, so they are checked later and recorded in the **Events** view:

- An entry that contains the LAN gateway or overlaps a directly connected network. Routing it would cut this computer off from its LAN.
- An entry that covers a built-in VPN's own server. Routing it would send the tunnel into itself.
- For WireGuard, an address no peer's `AllowedIPs` covers. WireGuard would drop its packets.

## Overlaps

Allowed. The longest prefix wins, so a `/32` inside another VPN's CIDR leaves through the `/32`'s VPN.
