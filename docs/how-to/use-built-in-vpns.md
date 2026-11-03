# Use built-in WireGuard, Outline and proxies

The helper can run WireGuard and Outline tunnels and tunnels through a SOCKS5 or HTTP proxy itself, several at once,
alongside VPN apps. Each carries only its own list.

Turn off the same tunnel in the WireGuard or Outline app first. One key used from two places makes
the server see two devices sharing it.

## Add a profile

In the **VPN** tab, under **Built-in VPNs**, choose **Import WireGuard .conf…**, **Add Outline Key…**, **Add SOCKS5 Proxy…** or **Add HTTP Proxy…**.

Or from the command line:

```bash
routewise profile import-wireguard ~/office.conf --name Office --auto
pbpaste | routewise profile import-outline --name Travel
echo socks5://127.0.0.1:1080 | routewise profile import-socks5 --name Laptop
pbpaste | routewise profile import-http --name Work
routewise profile list
routewise profile connect Office
routewise profile disconnect Office
routewise profile remove Travel
```

`--auto` connects the profile whenever the helper starts. An Outline key or a proxy address is read from stdin or
a hidden prompt, never an argument, so it stays out of your shell history. A proxy address is
`socks5://[username:password@]host:port` or `http://[username:password@]host:port`, with the username and password
percent-encoded.

## Give it a list

Choose **Edit Domains…** on its card. An entry that covers the tunnel's own server is refused, because it
would route the tunnel into itself.

## What the states mean

| State | Meaning | Its entries |
|---|---|---|
| connecting | Tunnel created, not yet proven to work | Wait for the tunnel for up to 10 s, then go direct until it is proven |
| connected | WireGuard handshake within 180 s; Outline DNS probe answered; proxy answered and accepted the login | Go through the tunnel |
| error | WireGuard: no first handshake after 30 s, or the last is older than 180 s. Outline and proxies: 3 probes in a row failed, 30 s apart. The helper keeps retrying | Go direct |
| needsCredentials | Imported from an export, which holds no secrets. Add the `.conf` or key again | Go direct |

## Before you use a proxy

- **The connection to a proxy is not encrypted.** Anyone on the network to it can read the password. Through SOCKS5 they can
  read any traffic not already encrypted, such as plain HTTP, and an HTTP proxy shows at least the sites you connect to. A proxy
  on the Internet with no password is open to anyone. The app warns about one and lets you add it. An `https://`
  proxy, which encrypts the connection to it, is not supported.
- **A password is optional.** A SOCKS5 proxy that wants none still connects if you give one. If a proxy wants one and you gave
  none or the wrong one, the profile's error says so.
- **An HTTP proxy must support `CONNECT`, and many allow it only to port 443.** Then HTTPS works and plain HTTP or any other
  port through it fails, even when the profile shows as connected. RouteWise sees only addresses, so a proxy that filters by
  site name cannot match its rules.
- **UDP may not get through.** An HTTP proxy cannot carry it and many SOCKS5 proxies do not. QUIC then fails and apps fall back to
  TCP by themselves. DNS always goes over TCP, so lookups through the tunnel work anyway, unless the proxy blocks port 53.
- **"Connected" means the proxy answers and accepts the login.** RouteWise asks it to reach `1.0.0.1:443`, and an answer that
  the address is unreachable or forbidden still counts, because a company proxy may reach only company addresses. So a proxy
  that has lost its own connection can show as connected while its traffic fails.
- **A proxy on this machine, such as `ssh -D`, cannot be the [default VPN](set-default-vpn.md).** What it connects onward to
  would enter the tunnel it serves. It can still carry a list, as long as the list does not cover the address it connects to.
- **A proxy on this machine must not make the onward connections itself.** With `ssh -D` the far end makes them. A proxy
  installed here, such as tinyproxy or Dante, reaches `1.0.0.1` for the health check through the tunnel it serves, so the
  profile stays at "connecting".

## Good to know

- **Quitting the app disconnects them**, waiting at most 5 seconds. Closing the window does not. VPN apps
  are left alone either way.
- **Secrets** stay in the root-only database and are never returned by the app, the RPC, exports or logs.
- **OpenVPN and AWS are not built in.** [Use the app](use-vpn-apps.md).
