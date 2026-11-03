# 0007 HTTP Proxies Through CONNECT

Date: 2026-11-03

## Status

Accepted

## Context

HTTP proxies are at least as common as SOCKS5 ones. [Decision 0006](0006-socks5-as-a-built-in-tunnel.md) gives a proxy a tunnel, whose flows reach only addresses and ports, as raw streams.

## Decision

An HTTP proxy is a built-in kind beside SOCKS5, sharing its tunnel, health rule and DNS over TCP. Every TCP flow becomes a `CONNECT` to its IP and port, with Basic authentication when there is a login. A health check counts 200, 403, 502, 503 and 504 as the proxy having answered, and any other answer as down.

## Alternatives Considered

1. Rewriting plain HTTP on port 80 into absolute-URI requests, which proxies that refuse `CONNECT` to port 80 would accept. The tunnel would have to parse every HTTP stream it carries, for one port.
2. An `https://` proxy, with TLS to the proxy. It would protect the password, and it is left out until someone needs one.

## Consequences

A proxy that allows `CONNECT` only to port 443, as many do, carries HTTPS and nothing else, and can still show as connected. A proxy that filters by site name sees only addresses, so its rules may not match. An HTTP proxy cannot carry UDP. The answer to `CONNECT` comes from someone else's machine and is read by a root process, so it is capped at 64 KiB.
