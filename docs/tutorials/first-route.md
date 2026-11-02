# Your first route

In about ten minutes you will install RouteWise, send one domain through a VPN, and see
for yourself that it went there while the rest of your traffic did not.

You need a Mac, and either a full-tunnel VPN app or a WireGuard `.conf` file. The steps use a
built-in WireGuard tunnel because it needs nothing else installed.

## 1. Install

```bash
git clone https://github.com/quocln/routewise.git
cd routewise
sudo make install
```

The first build takes around ten minutes. When it finishes, RouteWise opens and shows an icon
in the menu bar.

The command line tool is the helper itself. Put it on your `PATH`:

```bash
sudo mkdir -p /usr/local/bin
sudo ln -sf /Library/PrivilegedHelperTools/com.routewise.helper /usr/local/bin/routewise
routewise status
```

You should see `Daemon:  running`.

## 2. Add a VPN

1. Open the **VPN** tab.
2. Under **Built-in VPNs**, choose **Import WireGuard .conf…** and pick your file.
3. Press **Connect** on the new card.

The card reads **Connected** once the tunnel has completed a handshake.

If the same tunnel is on in the WireGuard app, turn it off first. One key used from two places
makes the server drop one of them.

## 3. Add a domain

1. On the card, choose **Edit Domains…**. This opens the VPN's list in the **Domains** tab.
2. Add a domain your VPN can reach. This tutorial uses `ifconfig.me`, because it tells you
   which address you came from.

## 4. See it work

Ask the system where that traffic goes:

```bash
routewise check ifconfig.me
```

Each address reads `VPN`, with the tunnel's interface. Now ask the site itself, and compare with
a domain you did not list:

```bash
curl -4 https://ifconfig.me    # the VPN's address
curl -4 https://icanhazip.com  # your own address
```

The first shows the VPN's address and the second shows your own. That is the whole idea: one
domain in the tunnel, everything else direct.

## 5. Watch it happen

Open the **Activity** tab and choose **Events**. You can see the route being added for
`ifconfig.me`, with the list that asked for it. Choose **Connections** to see each connection and
where it went.

## Where next

- [Use your VPN app](../how-to/use-vpn-apps.md) instead of a built-in tunnel.
- [Route a whole domain](../how-to/manage-domains.md) with a wildcard.
- [Send everything else through a VPN](../how-to/set-default-vpn.md) too.
- [How routing decisions are made](../explanation/routing.md).
