# Use a VPN app

RouteWise works with full-tunnel VPN apps: AWS Client VPN, OpenVPN with `redirect-gateway def1`,
`wg-quick`, and NetworkExtension clients such as the WireGuard app.

1. Connect the VPN as usual.
2. RouteWise shows a banner: **Manage this VPN**. Choose it once. The answer is remembered, and
   a Homebrew upgrade does not ask again.
3. Add entries to its list in the **Domains** tab.

From then on, only listed destinations use that VPN. To hand it back, remove it under **VPN apps** in
the **VPN** tab. Its catch-all routes return.

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
