# Back up and move your configuration

```bash
routewise config export my-routewise.json
routewise config import my-routewise.json
```

The same actions are in **Settings**, as **Export…** and **Import…**. Omit the file to print to stdout. Import needs `sudo`
only when the helper is not running.

**What the file holds:** DNS settings, the routing mode and default VPN, every domain list, the allowed VPNs in priority
order, built-in profiles without their secrets, and history settings.

**What it leaves out:** secrets, and machine-specific settings such as the log file. A built-in profile comes back in the
`needsCredentials` state; add its `.conf` or key again.

**Import replaces everything at once**, after checking the whole file. If any part is invalid, nothing changes. If it changed
the DNS servers, cache TTL or routing mode, restart the helper to apply them:

```bash
sudo routewise restart
```

Automatic backups are described in [Files and logs](../reference/files-and-logs.md#backups-and-recovery).
