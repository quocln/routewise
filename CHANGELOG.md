# Changelog

Notable changes to RouteWise. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Find VPN apps before they connect.** **Scan for VPN apps** and **Add app...** under **VPN apps**,
  on macOS, Linux and Windows.

### Changed

- VPN apps allowed on Linux and Windows show the product's name instead of the file name.

## [1.0.0] - 2026-11-02

First version.

### Added

- **Routing by name.** Send chosen domains, wildcards such as `*.corp.example.com`, IPv4 addresses
  and CIDRs through a VPN, and everything else direct. Routes follow a domain's IP changes.
- **Several VPNs at once.** Each VPN has its own list, plus an **Any VPN** list and a priority order.
  A VPN is managed only after you allow it.
- **VPN apps and built-in tunnels.** Works with full-tunnel apps such as AWS Client VPN, OpenVPN and
  WireGuard. The helper can also run WireGuard and Outline tunnels itself.
- **Default VPN.** Traffic in no list can go through a VPN you pick, and either go direct or switch to
  another VPN when it drops.
- **DNS.** Wildcard names are routed before the app gets its answer. A slow server is backed up by the
  next one after 200 ms. The VPN's own DNS servers can be asked first. **Clear DNS Cache** and
  **Clean DNS** are in Settings.
- **See what goes where.** The Activity tab, `routewise activity`, `routewise history` and
  `routewise check`.
- **Dashboard.** A tab and tray rows for CPU, memory, disk and network.
- **App and command line.** An app with a tray menu for macOS, Linux and Windows, and the `routewise`
  command.
- **Configuration export and import**, without secrets.
- **Error reporting** to your own Sentry-compatible server. Nothing is sent until you set it up.
- **Diagnostics.** `routewise debug profile {cpu|heap|mutex}` records a profile of the running helper
  without a restart.
