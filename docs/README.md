# Documentation

Organized by what you need right now, following [Diátaxis](https://diataxis.fr/). Each page
does one of these four jobs, and links to the others rather than repeating them.

## Tutorials

Learn by doing, start to finish.

- [Your first route](tutorials/first-route.md)

## How-to guides

Get a specific thing done.

- [Install, update and remove](how-to/install.md)
- [Manage domain lists](how-to/manage-domains.md)
- [Use a VPN app](how-to/use-vpn-apps.md)
- [Use built-in WireGuard, Outline and proxies](how-to/use-built-in-vpns.md)
- [Set a default VPN](how-to/set-default-vpn.md)
- [See what goes through the VPN](how-to/inspect-traffic.md)
- [Use the VPN's DNS and clear DNS](how-to/manage-dns.md)
- [Back up and move your configuration](how-to/export-config.md)
- [Report errors to your own server](how-to/report-errors.md)
- [Release](how-to/release.md)
- [Troubleshoot](how-to/troubleshoot.md)
- [Contribute](how-to/contribute.md)

## Reference

Look up exact facts.

- [Command line](reference/cli.md)
- [Settings](reference/settings.md)
- [List entries](reference/list-entries.md)
- [Files and logs](reference/files-and-logs.md)
- [Helper RPC](reference/rpc.md)
- [Platforms](reference/platforms.md)

## Explanation

Understand how it works and why.

- [Architecture](explanation/architecture.md)
- [How routing decisions are made](explanation/routing.md)
- [DNS](explanation/dns.md)
- [What RouteWise can and cannot see](explanation/visibility.md)
- [Security model](explanation/security.md)

## Project records

- [Changelog](../CHANGELOG.md)
- [Decisions](decisions/README.md): why lasting choices were made.

## Keeping these docs true

- One fact lives on one page. Others link to it.
- A change to behavior updates its page in the same change.
- Reference pages follow the code: CLI flags from `--help`, settings from `config.Settings`,
  RPC methods from `rpcMethods`. When they disagree, the code is right.
- A claim about what was tested belongs on [Platforms](reference/platforms.md), not scattered
  through the guides.
