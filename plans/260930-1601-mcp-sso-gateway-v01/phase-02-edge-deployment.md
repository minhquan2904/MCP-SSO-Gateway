---
status: completed
priority: P1
dependsOn:
  - phase-01-core-gateway.md
---

# Phase 02: Enforce the Edge and Deployment Contract

## Purpose

Make nginx and the packaged gateway one security contract. This phase resolves the current demo's two gaps: it cannot safely distinguish token-exchange MCP routing from no-credential HTTP API routing, and it does not bind the selected server to the original protected request URI.

## Files

| Path | Action | Required behavior |
|---|---|---|
| `deploy/nginx/mcp-gateway.locations.conf` | create | Default-denies every gateway path except `/auth/`; blocks every public spelling/method of introspection; hides gateway-control response headers outside internal auth requests; defines status JSON responses and original-URI forwarding. |
| `deploy/nginx/mcp-gateway-mcp.conf` | create | Clears all client-supplied gateway headers, exchanges personal authorization for the configured upstream bearer token, then forwards only validated `X-MCP-Gateway-User`. |
| `deploy/nginx/mcp-gateway-http-api.conf` | create | Clears client `Authorization` and all client-supplied gateway headers, forwards only the validated user identity, and never constructs an empty bearer credential. |
| `deploy/docker-compose.example.yml` | create | Uses `internal: true` authz and per-upstream networks plus a gateway-only `idp-egress` network for an external HTTPS identity provider; publishes only nginx. |
| `Dockerfile`, `docker/entrypoint.sh`, `docker/healthcheck.py` | create | Builds the package, starts one non-root worker with proxy headers disabled, and exposes health only internally. |
| `.env.example`, `examples/registry.yaml`, `examples/policy.yaml` | create | Provides a schema-valid, secret-free deployment configuration. |
| `tests/test_nginx_contract.py`, `tests/test_compose_hardening.py` | create | Self-contained contract/hardening checks; no sibling repository dependency. |

## Steps

1. Define the nginx variables at each protected location: selected registry server and original protected request URI. Pass both only to the internal auth subrequest; clients cannot supply or override either value. Before proxying, clear `X-MCP-Gateway-Server`, `X-MCP-Gateway-User`, and `X-MCP-Gateway-Upstream-Token`, then set only validated values needed by the selected upstream branch.
2. Nginx default-denies gateway routing. Only `^~ /auth/` may proxy to the public gateway app; it clears all gateway-control request headers and `proxy_hide_header`s all gateway-control response headers. Every other path/method returns 404 without proxying. The introspection handler is reachable solely through the internal auth subrequest on `authz`.
3. In `mcp_gateway.introspect`, normalize the original URI as a path without query/fragment, look up the selected registry entry, and reject if it differs from that entry's configured path prefix. Reject traversal, encoded-separator ambiguity, or a missing original-URI header rather than attempting recovery.
4. Use `location ^~` for every protected prefix. Keep the auth subrequest location `internal`; block direct nginx requests to it. Test `/_authz`, `/introspect`, `/introspect/`, `//introspect`, `/%69ntrospect`, `/introspect;x`, and every non-auth method: all must return 404 without reaching the handler. Return explicit JSON 401/403 responses for MCP-client usability.
5. Split the two upstream contracts. The MCP snippet can set `Authorization: Bearer <gateway result>` only after a successful result with an upstream token. The HTTP API snippet must clear `Authorization` and must not expose the upstream-token response header.
6. Build the gateway image from the public package with a regenerated frozen lockfile. Run as non-root, read-only root filesystem, tmpfs `/tmp`, dropped capabilities, `no-new-privileges`, resource limits, named writable data volume, health check, and exactly one Uvicorn worker.
7. Build the compose network model: nginx and gateway alone share `authz`; the gateway alone joins the non-internal `idp-egress` network to reach the external HTTPS identity provider (`https://idp.example.com`); each upstream gets its own `internal: true` network shared only with nginx. `authz` is `internal: true`. The production example contains no Keycloak service (decision 2026-10-01: external HTTPS IdP; Compose Keycloak remains demo-only in Phase 03). No gateway/upstream ports are published; only nginx binds loopback in the example.
8. Use distinct read-only service-scoped secret mounts. No service receives a shared secret volume: the gateway gets OIDC client, session, and needed upstream-token files; each upstream gets only its own token. Secrets are directory-scoped volumes below `MCP_GATEWAY_SECRETS_DIR`.
9. Add self-contained configuration/contract tests and an nginx config smoke parse. Replace, do not port, legacy tests that read internal sibling paths or assert private hosts.

## Acceptance

- Tests prove a request with an allowed token but a mismatched selected-server/original-URI pair is denied before upstream-token read.
- Tests prove a non-nginx peer, direct `/_authz` request, every public introspection-path/method variant with a valid token, missing/invalid Bearer credential, denied grant, missing registry server, unreadable upstream token, and valid request produce respectively 403, nginx-internal denial, 404 with no gateway headers, 401, 403, 404, 503, and 200.
- A contract test proves `mcp` forwards its own upstream bearer token and `http_api` forwards an empty `Authorization` header plus only `X-MCP-Gateway-User`; spoofed client `X-MCP-Gateway-Server`, `X-MCP-Gateway-User`, and `X-MCP-Gateway-Upstream-Token` never reach either upstream.
- Compose hardening tests prove no secret value is an environment variable; each service mounts only allowed read-only secret volumes; no gateway/upstream port is published and no Keycloak service exists; `authz` has only nginx/gateway and is internal; `idp-egress` has only the gateway; each upstream network is internal and shared by only nginx plus that one upstream; caller allowlists contain exact hostnames only; and runtime has listed least-privilege settings.

## Exit Gate

The public README/deploy documentation can state “nginx is the only ingress and introspection caller” without relying on an undocumented container, header, or operator convention.
