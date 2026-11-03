# Command line

The tool is one binary, which is also the helper. On macOS it is at
`/Library/PrivilegedHelperTools/com.routewise.helper`. See
[Install](../how-to/install.md#macos) to put it on your `PATH`. `<command> --help` is always current.

Most commands talk to the running helper. Changes need the console user or root: see the
[security model](../explanation/security.md).

## Status and inspection

| Command | Does |
|---|---|
| `routewise status` | Helper, VPNs, routes, default VPN, DNS |
| `routewise check <host>` | Where traffic to a host, IP or URL leaves, by asking the kernel |
| `routewise list-routes` | Routes RouteWise added |
| `routewise activity [-f] [-n N]` | Recent routing events and DNS answers. `-f` follows |
| `routewise history [flags]` | Connections this computer started |

`history` flags: `-n N`, `--since 1h\|24h\|7d`, `--search <text>`, `--vpn-only`, `--direct-only`, `-f`.

## Domain lists

These edit the **Any VPN** list. Per-VPN lists are edited in the app.

| Command | Does |
|---|---|
| `routewise add-domain <entry>` | Add a [list entry](list-entries.md) |
| `routewise remove-domain <entry>` | Remove one |
| `routewise list-domains` | List them |

## Built-in VPNs

| Command | Does |
|---|---|
| `routewise profile list` | Profiles and their state |
| `routewise profile import-wireguard <file> [--name N] [--auto]` | Import a `.conf` |
| `routewise profile import-outline [--name N] [--auto]` | Import an access key, from stdin or a hidden prompt |
| `routewise profile import-socks5 [--name N] [--auto]` | Import a proxy as `socks5://[username:password@]host:port`, from stdin or a hidden prompt |
| `routewise profile import-http [--name N] [--auto]` | Import a proxy as `http://[username:password@]host:port`, from stdin or a hidden prompt |
| `routewise profile connect <name\|id>` | Connect |
| `routewise profile disconnect <name\|id>` | Disconnect |
| `routewise profile remove <name\|id>` | Remove the profile, its credentials and its list |

## Configuration

| Command | Does |
|---|---|
| `routewise config export [file]` | Write the routing configuration, to stdout without a file |
| `routewise config import <file>` | Replace it. See [how](../how-to/export-config.md) |

## Service

| Command | Does |
|---|---|
| `routewise start [-f]` | Run the helper. launchd, systemd or the Windows service manager normally does this |
| `routewise stop` | Stop the running helper. launchd starts it again on macOS: [stop it for good](../how-to/install.md#macos) |
| `routewise restart` | Restart it |
| `routewise service install\|uninstall` | Linux and Windows: install or remove the helper as a service |

## Diagnosis

| Command | Does |
|---|---|
| `routewise debug profile {cpu\|heap\|mutex} [--seconds N] [-o file]` | Record a runtime profile for `go tool pprof`, up to 300 s |

## Global flags

| Flag | Does |
|---|---|
| `-v`, `--verbose` | More output |
| `--config <file>` | Use this config file when no helper is running |
| `--insecure-config` | Skip the config file's security checks. Not recommended |
