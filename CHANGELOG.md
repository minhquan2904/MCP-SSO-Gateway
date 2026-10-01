# Changelog

## 0.1.0 (unreleased)

- Added OIDC authorization-code sign-in with PKCE and a browser page for issuing
  and revoking hashed personal access tokens; administrative CLI can issue,
  revoke, and list tokens.
- Added static YAML registry and policy, loaded at startup; changes require a
  gateway restart. Policy grant labels are local, not Keycloak roles/groups.
- Added private nginx introspection, MCP upstream bearer-token exchange, and
  HTTP API routing without forwarding the client's Authorization header.
- Added SQLite-backed token state with one gateway worker, audit output,
  service-scoped file secrets, and nginx-only ingress.
- Added external-HTTPS-IdP production example with TLS nginx and gateway-only
  IdP egress; loopback-only HTTP Keycloak demo and bootstrap probe remain
  intentionally separate.
- Added CI and release checks for frozen dependencies, lint/tests, secrets,
  vulnerability audits, image build/scan, and Compose smoke. No public image,
  tag, or push is implied by this entry.

Not shipped in v0.1: Keycloak roles/groups authorization, OpenFGA, policy
caching, or MCP OAuth authorization-server discovery. MCP clients use PATs.
