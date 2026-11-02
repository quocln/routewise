# See what goes through the VPN

## Check one host

```bash
routewise check jira.corp.example.com
```

Or use the check box at the top of the **Routes** tab. The verdict is the kernel's, so it is what traffic will really do.

## See what has been happening

The **Activity** tab has three views, sharing one toolbar for time range, list, VPN and search:

| View | Shows |
|---|---|
| **Connections** | Each new outbound connection and where it went |
| **DNS** | DNS answers this computer received, each marked VPN or direct |
| **Events** | VPNs connecting and disconnecting, routes added and removed, routes refused with the reason |

A listed name that went direct because its VPN was down carries an orange warning.

From the command line:

```bash
routewise activity -f
routewise history --since 24h --search example.com
routewise history --vpn-only -n 200
```

## See the routes

The **Routes** tab lists every route RouteWise added, with the entry and list that asked for it. Or:

```bash
routewise list-routes
```

## Turn the history off

**Settings** has a switch and a retention period, 1 to 90 days, 7 by default. The history lists every host this computer
contacted, never packet contents.

For what these views cannot see, read [What RouteWise can and cannot see](../explanation/visibility.md).
