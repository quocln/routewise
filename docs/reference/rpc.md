# Helper RPC

The app and the CLI talk to the helper with newline-delimited JSON-RPC 2.0 on its [socket](files-and-logs.md#locations). `internal/api`
holds the types and `rpcMethods` in `internal/api/methods.go` is the authoritative list. `desktop/src/lib/api/*.gen.ts` is generated from
them.

This interface is internal: the app and the helper ship together, and it may change.

## Auth levels

| Level | Who |
|---|---|
| Public | Anyone the socket's permissions admit |
| Private read | Root or the console user, because the answer is private |
| Mutate | Root or the console user, and recorded in the audit log |

## Methods

| Method | Auth | Does |
|---|---|---|
| `status.get` | Public | Helper, tunnels, routes, DNS and default VPN state |
| `settings.get` | Public | Settings the app can change |
| `routes.list` | Public | Routes RouteWise added |
| `routes.check` | Public | Where a host's traffic leaves |
| `domains.list` | Public | One list's entries |
| `config.export` | Public | The routing configuration, no secrets |
| `activity.list` | Private read | Activity events, with long poll |
| `access.list` | Private read | Connection history, with long poll |
| `prefs.get` | Private read | This user's app preferences |
| `telemetry.get` | Private read | Error-reporting settings, including the DSN |
| `profiles.list` | Private read | Built-in VPNs, without secrets |
| `vpn.scan` | Private read | VPN clients installed here that are not allowed yet |
| `debug.profile` | Private read | A runtime profile |
| `settings.set` | Mutate | Change settings |
| `domains.add`, `domains.remove`, `domains.set` | Mutate | Edit a list |
| `config.import` | Mutate | Replace the routing configuration |
| `vpn.setAllowed` | Mutate | Allow or revoke a VPN client |
| `vpn.resolve` | Mutate | The VPN client a chosen app or program stands for |
| `dns.clearCache`, `dns.clean` | Mutate | [Clear DNS](../how-to/manage-dns.md#clear-dns) |
| `access.clear` | Mutate | Delete the connection history |
| `prefs.set` | Mutate | Store one app preference |
| `telemetry.set` | Mutate | Change error reporting |
| `profiles.import`, `profiles.update`, `profiles.remove`, `profiles.connect`, `profiles.disconnect` | Mutate | Manage built-in VPNs |

A request is limited to 1 MiB.
