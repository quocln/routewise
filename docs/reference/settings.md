# Settings

The helper stores these in its [database](files-and-logs.md). Change them through the app, or through
[`config import`](../how-to/export-config.md). `config.Settings` in `internal/config/settings.go` is the
authoritative list.

"Applies" says when a change takes effect. "Restart" means `routewise restart`.

## DNS

| Key | Default | Applies | Meaning |
|---|---|---|---|
| `dns.servers` | `8.8.8.8`, `1.1.1.1` | Restart | Servers for resolving listed names |
| `dns.cache_ttl` | `300` | Restart | Seconds between re-resolving exact names |
| `dns.use_vpn_dns` | `false` | At once | Ask the VPN's DNS servers first. See [DNS](../explanation/dns.md) |

## Routing

| Key | Default | Applies | Meaning |
|---|---|---|---|
| `routing.mode` | `inverted` | Restart | `inverted` takes a VPN's catch-all routes away. `additive` leaves them and only adds routes |
| `routing.allow_ipv6` | `false` | At once | Let IPv6 through instead of blocking it. See [IPv6](../explanation/routing.md#ipv6) |
| `routing.default_vpn` | none | At once | Client ID of the [default VPN](../how-to/set-default-vpn.md). Needs `inverted` |
| `routing.default_vpn_fallback` | none | At once | Client ID that takes over while it is down. None means direct |
| `routing.default_vpn_except` | none | At once | Domains, wildcards, IPs and networks that go direct instead of through the default VPN. A connected VPN's list still wins |

## History

| Key | Default | Applies | Meaning |
|---|---|---|---|
| `history.enabled` | `true` | At once | Record connections and activity |
| `history.retention_days` | `7` | At once | How long to keep them, 1 to 90 |

## Error reporting

Nothing is sent without a DSN. See [how](../how-to/report-errors.md).

| Key | Default | Meaning |
|---|---|---|
| `telemetry.dsn` | none | Your Sentry-compatible server |
| `telemetry.errors` | `true` | Errors and crashes |
| `telemetry.sessions` | `true` | Sessions |
| `telemetry.logs` | `true` | Logs |
| `telemetry.traces` | `true` | Performance traces |
| `telemetry.traces_sample_rate` | see code | Share of traces sent |

## Daemon

Specific to the machine, so exports leave them out, and no command changes them.

| Key | Default | Meaning |
|---|---|---|
| `daemon.poll_interval` | `1` | Seconds between checks for VPNs |
| `daemon.pid_file` | `/var/run/routewise.pid` on macOS | PID file |
| `daemon.log_file` | `/var/log/routewise.log` on macOS | Log location. Daily files sit beside it |
| `daemon.log_level` | `info` | `debug`, `info`, `warn` or `error` |

## Limits

At most 500 list entries in total.
