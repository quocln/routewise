# Use built-in WireGuard and Outline

The helper can run WireGuard and Outline tunnels itself, several at once, alongside VPN apps. Each
carries only its own list.

Turn off the same tunnel in the WireGuard or Outline app first. One key used from two places makes
the server see two devices sharing it.

## Add a profile

In the **VPN** tab, under **Built-in VPNs**, choose **Import WireGuard .conf…** or **Add Outline key…**.

Or from the command line:

```bash
routewise profile import-wireguard ~/office.conf --name Office --auto
pbpaste | routewise profile import-outline --name Travel
routewise profile list
routewise profile connect Office
routewise profile disconnect Office
routewise profile remove Travel
```

`--auto` connects the profile whenever the helper starts. An Outline key is read from stdin or a hidden
prompt, never an argument, so it stays out of your shell history.

## Give it a list

Choose **Edit Domains…** on its card. An entry that covers the tunnel's own server is refused, because it
would route the tunnel into itself.

## What the states mean

| State | Meaning | Its entries |
|---|---|---|
| connecting | Tunnel created, not yet proven to work | Wait for the tunnel for up to 10 s, then go direct until it is proven |
| connected | WireGuard handshake within 180 s; Outline DNS probe answered | Go through the tunnel |
| error | WireGuard: no first handshake after 30 s, or the last is older than 180 s. Outline: 3 probes in a row failed, 30 s apart. The helper keeps retrying | Go direct |
| needsCredentials | Imported from an export, which holds no secrets. Add the `.conf` or key again | Go direct |

## Good to know

- **Quitting the app disconnects them**, waiting at most 5 seconds. Closing the window does not. VPN apps
  are left alone either way.
- **Secrets** stay in the root-only database and are never returned by the app, the RPC, exports or logs.
- **OpenVPN and AWS are not built in.** [Use the app](use-vpn-apps.md).
