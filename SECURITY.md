# Security policy

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository if enabled. If it
is unavailable, open an issue asking the maintainers for a private reporting
channel **without** including an exploit, token, secret, internal hostname, or
other sensitive detail. Do not publish a proof of concept before the maintainers
have coordinated remediation and disclosure.

Include affected version, impact, reproduction steps, and a minimal redacted
example in the private report. Revoke any exposed token and rotate any exposed
upstream, OIDC client, or session secret immediately.

## v0.1 security boundary

- Production requires nginx-only ingress with TLS before any session cookie or PAT
  crosses a network. The sample nginx publishes TLS on host loopback; an operator
  must preserve TLS if exposing it through another edge. The Keycloak HTTP demo is
  loopback-only and intentionally insecure, not a production topology.
- The gateway and upstreams must have no published ports. Only nginx may call
  `/introspect` over the internal `authz` network; nginx must not expose that route
  or its internal `/_authz` subrequest to clients.
- Strip client-supplied gateway-control headers at nginx. Upstreams may trust
  `X-MCP-Gateway-User` only when received from nginx on their isolated private
  network; direct upstream access bypasses the header trust boundary.
- Mount separate secret files into only the services that consume them; keep
  secret values out of environment variables, logs, issues, commits, and images.
  Protect SQLite state and audit files. Run exactly one gateway worker.
- Static YAML policy and registry changes require a gateway restart. Grant labels
  in that policy are not IdP roles; Keycloak roles/groups and OpenFGA are not
  authorization sources in v0.1. PAT mode is not MCP OAuth AS discovery.

Before any public release, run the CI gates and the out-of-band release scan
[described in CONTRIBUTING.md](CONTRIBUTING.md). A passing generic secret scan
cannot substitute for private-reference deny patterns.
