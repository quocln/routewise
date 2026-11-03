# 0005 Default VPN Exceptions

Date: 2026-11-03

## Status

Accepted

## Context

A default VPN takes everything no list claims, and some traffic must stay off it, such as a bank that refuses VPN addresses. The list of what to except can also name something a VPN list holds, and the kernel's longest-prefix rule alone would decide that the wrong way round: an excepted `10.0.0.5` would beat a list's `10.0.0.0/8`.

## Decision

An exception is a route of its own through the LAN gateway, which outranks the role's `/2` routes by being longer. A list outranks an exception while the list's VPN is connected: an exception gives up a host route a list wants, and is not added at all inside a network a list routes. Once that VPN is down the exception decides, so the name goes direct instead of into the default VPN.

Names get their addresses two ways. Each sync resolves the exact ones, and a resolver file sends lookups through the forwarder, which routes what an app is told before the app is told it. Only the second covers a wildcard, or a CDN whose answer changes per lookup.

The list lives in `routing.default_vpn_except`, is kept when the default VPN is cleared, and has effect only while a tunnel holds the role.

## Alternatives Considered

1. A route manager of its own, as a tunnel has. Its journal does not record host routes, which a tunnel's going away removes, and a route through the LAN would outlive a crash. Its route events also report everything as going through a VPN.
2. An exception that always wins, whatever the lists say. Simpler, but a name in a VPN's list exists to go through that VPN.
3. A choice of where an exception goes. Nobody asked for it, and "direct" is the only answer that needs no VPN to be up.

## Consequences

Routes through the LAN outlive a crash, so the role's journal names them. A route that existed before is left alone rather than adopted, because a VPN app's route to its own server can lead through the LAN, and removing it would cut that VPN off. An exception's lookup still travels through whatever carries the DNS server, so an answer can be for the VPN's region.
