# Use the VPN's DNS and clear DNS

## Use the VPN's DNS servers

Turn this on when internal names exist only in your company's DNS.

In the **VPN** tab, under **DNS**, turn on **Use the VPN's DNS servers**. It applies at once. RouteWise then asks those
servers first, with `dns.servers` as the fallback.

## Clear DNS

Use these when names resolve to old addresses. Both are in the **Settings** tab, under **DNS**.

| Button | Does | Open connections |
|---|---|---|
| **Clear DNS Cache** | Empties RouteWise's cache and the system's | Unaffected |
| **Clean DNS** | The same, and removes routes learned from wildcard lookups. It asks first | Those over learned routes can drop until the next lookup routes them again |

Try **Clear DNS Cache** first.

How lookups work: [DNS](../explanation/dns.md).
