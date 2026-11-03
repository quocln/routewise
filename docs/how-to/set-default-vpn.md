# Set a default VPN

By default, traffic in no list goes direct. A default VPN carries that traffic instead. Listed domains keep
their own VPN.

1. Open the **VPN** tab and find **Default VPN**.
2. Under **Send other traffic through**, pick any allowed VPN, built-in or an app.
3. Under **If it goes down**, choose **Go direct** or **Switch to** another VPN.

With VPN2 as the default, VPN1 listing `a.com`, and VPN3 listing `c.com`:

| Request | Where it goes |
|---|---|
| `a.com` | VPN1. While VPN1 is down, VPN2 |
| `c.com` | VPN3. While VPN3 is down, VPN2 |
| `google.com`, in no list | VPN2 |
| A device on your LAN | Direct |

To keep something off the default VPN, add it under **Except these, which go direct**: a domain, a wildcard such
as `*.example.com`, an IPv4 address or a network. With `bank.example.com` excepted:

| Request | Where it goes |
|---|---|
| `bank.example.com` | Direct, whichever VPN carries other traffic |
| `bank.example.com`, also in VPN1's list | VPN1. While VPN1 is down, direct |
| `www.bank.example.com` | The default VPN. `bank.example.com` covers that exact name; add `*.bank.example.com` for the rest |

When the default VPN returns, traffic moves back. If the VPN you switch to is down as well, traffic goes
direct. `routewise status` prints a `Default:` line saying where that traffic goes now.

## Before you rely on it

- **Open connections drop when traffic moves.** Apps reconnect.
- **IPv6 is blocked** while a default VPN carries traffic, so nothing leaves around it. A site with only IPv6
  addresses stops working. **Allow IPv6** in **Settings** lifts this, and IPv6 traffic then goes direct.
- **DNS does not change.** If your resolver is on your LAN, it still sees the names you look up, even though the
  traffic goes through the VPN.
- **An exception follows addresses, not names.** Another site on the same address, as is common behind a CDN, goes
  direct too. A connection opened before you added the exception stays where it was until the app reconnects.
- **An excepted name is looked up through your DNS servers, which may be reached through the VPN.** The answer can
  then be for the VPN's region, and the traffic still goes direct to it. A site that serves by region may be slower or
  behave as if you were in that region. An IP or network exception avoids this.
- **A stuck VPN app keeps the traffic.** A VPN app counts as down only when its tunnel goes away, because RouteWise
  cannot test a tunnel it does not run. Disconnect it yourself. A built-in VPN is tested, and is replaced when it
  fails its health check.

## What may refuse the role

The VPN tab says why when one of these applies:

- A WireGuard profile whose `AllowedIPs` do not cover everything (`0.0.0.0/0`).
- On Linux, a VPN app that steers traffic with a policy rule, such as `wg-quick`. Use a built-in WireGuard profile.
- `routing.mode` set to `additive`.

## Side effects on macOS

- A program that binds its connection to the LAN interface, such as `curl --interface en0`, gets "Network is unreachable"
  for most addresses while the role is held. Normal programs are not affected.
- A VPN app that connects over IPv6 may lose its connection until **Allow IPv6** is on.

Why it works this way: [How routing decisions are made](../explanation/routing.md#the-default-vpn).
