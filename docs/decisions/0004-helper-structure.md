# 0004 Helper Structure

Date: 2026-11-02

## Status

Accepted

## Context

Adding the default VPN touched many files, overlapping timers each checked the routing table, and route changes started a process while holding the lock DNS answers wait for.

## Decision

- Decide routes in a pure function, `planRoutes`, and keep decisions in place from one `controlLoop`. Syncs stay outside that loop, because one can wait seconds on a DNS server.
- On macOS, use a routing socket for host and network routes and lookups, behind the command table's logic, falling back to `route(8)` on any unexpected kernel error. Changing the default route stays with `route(8)`: nothing else can cut the machine off so thoroughly, it is rare, and there is nothing to gain.
- Poll the helper's status once, in the Rust shell, and push it to the tray and the window. Profiles and routes in the window keep their own polling for now.

## Alternatives Considered

1. Split all of `Daemon` at once. Its tests reach into it, so moving everything would change many tests with no way to tell a move from a change of behavior. Instead the RPC interface is split, state is grouped, and the default VPN is the first separate component. Others follow when they are next changed.
2. A rewrite around actors or a new lock model. The risk is out of proportion in code that edits the routing table, and hot paths already run in nanoseconds.

## Consequences

`Daemon` still has about 190 methods. A new role or rule has a clear home.
