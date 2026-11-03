# Security model

The helper runs as root and rewrites routing. That is the risk everything here exists to contain.

## Who may do what

The socket lets local users connect, which is not enough to change anything. The helper asks the kernel who is on the other end of each connection, once, when it is accepted, so the identity cannot change
midway.

- **Public** calls read status and routes.
- **Private reads**, such as history or the DSN, and **all changes** need root or the user logged in at the console.
- **Every change** is recorded in the log as `accepted`, `denied` or `failed`, with who asked.

The levels live beside each method in [`rpcMethods`](../reference/rpc.md), so a method cannot exist without one. An unauthorized wiring fails closed.

Linux's socket is open to all users, because no group is shared by every desktop user, and the check above is what protects it. On Windows, clients also check that the pipe is served by the real service.

## Threats

| Threat | Mitigation |
|---|---|
| Another local account reroutes traffic | Peer check on every change |
| Another local account reads what you looked up | Private reads need the console user |
| Secrets leak | Credentials stay in the root-only database. Not returned by RPC, exports or logs. Outline keys and proxy addresses are not accepted as arguments |
| A hostile config or journal | Files are root-only. Journals are checked for owner, mode and size before being trusted |
| A swapped system tool | Tools run by absolute path. Each must be a root-owned regular file, not writable by others, checked every time |
| Routing that cuts off the machine | Entries overlapping the LAN are refused, and one route per destination is enforced across VPNs |
| A tunnel routed into itself | Entries covering a built-in VPN's server are refused |
| Overwriting another tool's resolver file | RouteWise touches a file only if it carries RouteWise's marker |
| Resource exhaustion | Timeouts, 1 MiB requests, and caps on entries, learned routes and DNS cache |

## Things it does not defend against

Root on the same machine. A compromised VPN server for traffic you send there. DNS answers from a server you told it to trust.
