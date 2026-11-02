# 0003 Hedged DNS Without Server Memory

Date: 2026-11-02

## Status

Accepted

## Context

The forwarder asked servers one after another, so a dead first server cost a full timeout on every lookup. RouteWise has no load balancing and needs none. Two fixes were weighed: remember which server failed and skip it, or ask the next
server when the first is slow.

## Decision

Hedge: ask the next server in the group after 200 ms with no reply, or at once on SERVFAIL or REFUSED. The first positive answer wins. There is no state.

Clearing DNS is a manual action with two buttons, Clear DNS Cache and Clean DNS, and no stored setting.

## Alternatives Considered

1. Stateful failover: faster when a server is dead for a long time, but it adds state that can be wrong, and needs a way to notice a server returning. Combining it with hedging remains possible.

## Consequences

A dead first server costs 200 ms per query, every time. A group of one gains nothing, and a dead server there still means waiting. Slow lookups send a second query, which a second server sees.
