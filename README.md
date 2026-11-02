# RouteWise

Send only the traffic you choose through a VPN, by domain name, and leave the rest on
your normal connection.

A full-tunnel VPN sends everything through the tunnel, which slows ordinary browsing and
can block services. RouteWise reverses that: you list the domains, wildcards, IPs or
networks that belong in the VPN, and everything else goes direct. It runs several VPNs at
once, each with its own list.

## Features

- **Routing by name:** domains, wildcards such as `*.corp.example.com`, IPv4 addresses and
  CIDRs. Routes follow a domain's IP changes.
- **Several VPNs at once:** VPN apps (AWS Client VPN, OpenVPN, WireGuard) and built-in
  WireGuard and Outline tunnels the helper runs itself.
- **Default VPN:** optionally send everything that is in no list through one VPN, with a
  fallback when it drops.
- **See what goes where:** connections, DNS answers and route events, and a check for any
  host.
- **Dashboard:** CPU, memory, disk and network, in the app and its menu.

## Quick start

On macOS, download `RouteWise-<version>-macos-universal.zip` from the
[latest release](https://github.com/quocln/routewise/releases/latest), then follow
[Install](docs/how-to/install.md#download-the-app).

To build from source instead, with Go, Rust (with the `aarch64-apple-darwin` and
`x86_64-apple-darwin` targets) and Node installed:

```bash
git clone https://github.com/quocln/routewise.git
cd routewise
sudo make install
```

This builds and installs the helper and `RouteWise.app`, then opens the app. Follow
[your first route](docs/tutorials/first-route.md) from there.

Linux and Windows are covered in [Install](docs/how-to/install.md).

## Documentation

| I want to | Go to |
|---|---|
| Learn by doing | [Tutorial: your first route](docs/tutorials/first-route.md) |
| Get something done | [How-to guides](docs/README.md#how-to-guides) |
| Look up a command, setting or path | [Reference](docs/README.md#reference) |
| Understand how it works and why | [Explanation](docs/README.md#explanation) |
| See what changed | [Changelog](CHANGELOG.md) |
| Work on the code | [Contribute](docs/how-to/contribute.md) |

## Status

Version 1.0.0. macOS is the primary platform. See
[what has been tested where](docs/reference/platforms.md).
