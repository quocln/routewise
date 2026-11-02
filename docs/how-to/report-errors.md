# Report errors to your own server

RouteWise can send errors, crashes, sessions, logs and performance traces to a Sentry-compatible server you run. Nothing is
sent until you give it a DSN.

1. Open **Settings** and find error reporting.
2. Paste your DSN.
3. Choose what to send. Each kind can be turned off.

The DSN is a credential for that server, so only the console user can read it back. Reports leave out your VPN profile names
and domains.
