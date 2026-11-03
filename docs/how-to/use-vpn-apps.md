# Use a VPN app

RouteWise works with full-tunnel VPN apps: AWS Client VPN, OpenVPN with `redirect-gateway def1`,
`wg-quick`, and NetworkExtension clients such as the WireGuard app.

1. Connect the VPN as usual.
2. RouteWise shows a banner: **Manage this VPN**. Choose it once. The answer is remembered, and
   a Homebrew upgrade does not ask again.
3. Add entries to its list in the **Domains** tab.

From then on, only listed destinations use that VPN. To hand it back, remove it under **VPN apps** in
the **VPN** tab. Its catch-all routes return.

## Set one up before it connects

In the **VPN** tab, under **VPN apps**:

- **Scan for VPN apps** lists the VPN apps and command-line clients on this computer. Choose
  **Manage** on the ones you want. A scan changes nothing by itself.
- **Add app...** takes an app or program you pick. RouteWise works out which part of it owns the
  tunnel, and refuses a program that could not.

You can then fill its list or make it the default VPN. RouteWise starts managing it the next time it
connects, and only if it creates a full tunnel.

What each platform can find:

| Platform | Found |
|---|---|
| macOS | Apps in `/Applications` and each user's `Applications` with a packet tunnel extension, the AWS VPN Client, and Homebrew's `openvpn` and `wireguard-go` |
| Linux | `openvpn`, `wireguard-go`, the WireGuard tools (as kernel WireGuard), OpenVPN 3 and the AWS VPN Client |
| Windows | AWS VPN Client, OpenVPN, OpenVPN Connect and WireGuard, under Program Files |

Not found, and refused by **Add app...**: macOS apps that use a system extension, because its path
changes with each update. They still get the banner when they connect. Windows only recognizes the
products above, installed under Program Files.

## Several at once

The order under **VPN apps** is the priority. It decides who gets an address two VPNs both want,
and which VPN carries the **Any VPN** list.

macOS allows about one NetworkExtension VPN at a time. Command-line clients, the AWS VPN Client and
built-in tunnels run alongside it and each other.

## What does not work

- **Split-tunnel configurations.** RouteWise recognizes a VPN by its catch-all routes, so a split
  configuration, including an AWS endpoint set up that way, is not detected.
- **Kill switches.** "Block untunneled traffic" or NetworkExtension `includeAllNetworks` drops what
  RouteWise sends outside the tunnel. Turn it off.
- **WireGuard with narrow `AllowedIPs`.** It only carries what `AllowedIPs` covers. A config without a
  catch-all is not detected.
