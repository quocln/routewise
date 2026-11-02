# Troubleshoot

Start with these. Most problems show up in one of them:

```bash
routewise status
routewise check <the-host-that-is-wrong>
tail -f /var/log/routewise-$(date +%F).log
```

## The helper is not running

`routewise status` says it is not running, or the app says it cannot reach the helper.

```bash
sudo launchctl print system/com.routewise.helper
sudo launchctl kickstart -k system/com.routewise.helper
```

On Linux use `systemctl status routewise`, and on Windows the Services app. The rest of this page gives macOS paths: see [Files and logs](../reference/files-and-logs.md) for the others.

`/var/log/routewise.log` holds crash output. If it has a stack trace, please report it.

If it says the daemon is already running but nothing is, remove the stale PID file:

```bash
sudo rm /var/run/routewise.pid
sudo routewise start
```

## A listed domain goes direct

1. `routewise check <host>` shows where it goes. `routewise status` shows which VPNs are up.
2. **Its VPN is down.** A listed name goes direct while its VPN is down, or follows the
   [default VPN](set-default-vpn.md) if you set one.
3. **Its address changed.** Routes are refreshed every `dns.cache_ttl`. [Clear DNS](manage-dns.md).
4. **An app uses its own DNS or IPv6.** See the next section.
5. **The entry was refused.** See [An entry is refused](#an-entry-is-refused).

## Wildcard domains are not routed

Read the `Wildcard:` line of `routewise status`.

- **`lookups under <suffix> go through RouteWise`:** it is active. If a name still goes direct, check that the app does not
  use its own DNS-over-HTTPS, such as Chrome's Secure DNS. Those lookups bypass the system.
- **No line:** no VPN with a wildcard list is connected.
- **`not active: ...`:** the message has the reason. Usually one of:
  - A resolver file RouteWise does not own exists at `/etc/resolver/<suffix>`. RouteWise never overwrites one.
  - Port 53053 is in use. Find out by what: `sudo lsof -nP -i :53053`.
  - With the VPN's DNS on, RouteWise is waiting for the VPN to publish its servers.

## Internal names do not resolve

Turn on [the VPN's DNS](manage-dns.md). With it off, names under a wildcard resolve through `dns.servers`, which know nothing
of internal names.

## The VPN is not detected

Only full-tunnel VPNs are. See [what does not work](use-vpn-apps.md#what-does-not-work). If it is detected but not managed, choose
**Manage this VPN** in the banner.

## An entry is refused

The **Events** view in the **Activity** tab has the reason. The rules are in [List entries](../reference/list-entries.md). A common
one: a CIDR that overlaps your own LAN is refused because routing it would cut you off from your network.

## Everything lost connectivity

If you have a default VPN, set it to **No VPN (direct)** first. That alone is often enough.

Otherwise stop the helper for good. It removes what RouteWise added to the routing table on the way out:

```bash
sudo launchctl bootout system/com.routewise.helper
```

`routewise stop` is not enough on macOS: launchd starts the helper again, and it applies your settings again.

## History or activity stopped recording

Routing still works but the **Activity** tab gains no rows, and the log has an error about writing history. The database was
damaged while running. Restart: `sudo routewise restart`. It is then rebuilt from its backup. See
[backups and recovery](../reference/files-and-logs.md#backups-and-recovery).

## More detail

For debug logging, [stop the service](install.md#macos) and run the helper in the foreground with `sudo routewise start -v`. To see where it spends its time, profile it without restarting:

```bash
routewise debug profile cpu --seconds 30
go tool pprof -top cpu.pprof
```

`heap` and `mutex` work the same way. A profile holds function names and counts, never the contents of memory.
