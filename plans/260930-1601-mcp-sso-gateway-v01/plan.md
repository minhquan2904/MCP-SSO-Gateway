---
status: in_progress
priority: P1
blockedBy: []
blocks:
  - v0.2-keycloak-policy
  - v0.3-openfga-distribution
---

# Implementation Plan: MCP SSO Gateway v0.1

> **Source:** `private/plan.md` (draft reviewed 2026-09-29)
> **Scope:** deliver one publishable v0.1 release. Do not implement the v0.2 Keycloak authorization backend or v0.3 OpenFGA/distribution work.

## Goal

Turn the current public demo into a standalone, generic MCP SSO Gateway that signs users in through OIDC, issues revocable personal tokens, authorizes each request from a static YAML policy, and exchanges a personal token for an upstream token at nginx. The release must preserve the public README security contract and contain no internal source, history, identifiers, topology, or secrets.

## Locked Decisions

| Concern | v0.1 decision |
|---|---|
| Public product name | `MCP SSO Gateway` in public text; `mcp_gateway` Python package; `MCP_GATEWAY_*` product configuration names |
| Authorization | `POLICY_BACKEND=static` only. Registry routing metadata lives in `registry.yaml`; grant-only policy lives in `policy.yaml`. Keycloak is the OIDC identity provider, not an authorization backend. |
| Policy grammar | `policy.yaml` has `roles: {role: [server-name]}` and `members: {role: [{issuer: <exact issuer>, subject: <exact sub>}]}`. Duplicate grants are harmless; undeclared server names fail boot. |
| Identity key | Persist `issuer`, `subject`, and `identity_id = base64url(SHA-256(issuer + NUL + subject))`; policy uses issuer/subject, audit and upstream user headers use `identity_id`, and a username claim is display-only. |
| Upstream kinds | `mcp` requires an `upstream_token_file`; `http_api` has no upstream credential and nginx must clear client `Authorization`. |
| Introspection boundary | A dedicated Compose `authz` network contains only nginx and gateway; no gateway port is published. nginx is additionally validated by TCP peer and binds the protected location's captured original URI to its configured registry path. Do not enable uvicorn proxy-header trust. |
| Session secret | `MCP_GATEWAY_SESSION_SECRET(_FILE)` must contain at least 32 non-whitespace UTF-8 bytes; startup rejects weaker values. |
| Token format and disclosure | `mcpgw_<43 base64url chars>_<8 lowercase SHA-256 checksum chars>`; store only a SHA-256 hash of the full token. Plaintext is allowed only in the one-time HTML issuance response and CLI `issue` stdout, never in client config, shell commands, logs, audit, or committed files. |
| OIDC transport | `OIDC_ISSUER` must match the validated ID-token `iss`. Different `OIDC_DISCOVERY_URL` is permitted only with `MCP_GATEWAY_ALLOW_INSECURE_OIDC=true` in the tracked demo; production defaults to HTTPS-only issuer/discovery. |
| Static policy refresh | Policy/registry load once at boot; grant changes require a gateway restart or redeploy. |
| Compatibility | No legacy headers, environment variables, token prefixes, imports, or config shims. |

## Normative Registry Schema

`registry.yaml` is the sole gateway source for server metadata; nginx upstream addresses remain operator-written deployment configuration. Every protected nginx location must declare the same `name` and `path` as its registry entry; the gateway rejects a mismatch at introspection time.

```yaml
servers:
  - name: echo
    client_name: echo
    title: Echo MCP
    description: Demo upstream
    path: /echo/
    kind: mcp
    upstream_token_file: /run/secrets/echo_token
    listed: true
  - name: status-api
    title: Status API
    description: Demo HTTP API
    path: /status/
    kind: http_api
    listed: false
```

| Field | Required | Rule |
|---|---|---|
| `name` | yes | Unique `^[a-z][a-z0-9-]{0,62}$`; nginx sends exactly this value. |
| `client_name` | no | Safe client-facing name; defaults to `name`; must match the same grammar. |
| `title`, `description` | yes | Non-empty plain text, escaped when rendered. |
| `path` | yes | Unique absolute trailing-slash prefix; no query, fragment, `..`, percent escapes, or overlapping prefixes. |
| `kind` | yes | `mcp` or `http_api`. |
| `upstream_token_file` | `mcp` only | Absolute readable regular file below the configured secrets directory; forbidden for `http_api`. |
| `listed` | no | Boolean, defaults to `true`; controls UI/client-config visibility only. |

The loader rejects unknown fields and a policy grant referring to any server absent from this file. Deployment locations own upstream host/port, but the shared registry fixture is used by loader and nginx-contract tests so server/path mappings cannot drift.

## Safety Boundary

`private/mcp-auth/` is an internal source snapshot for reference only. Never add it to the public release, copy untracked files, reuse internal commit history, or commit a raw extraction before the sensitive-data gate passes. `.gitignore` and `.dockerignore` must exclude `private/`; the release gate proves `git ls-files private/` is empty and the effective Docker build context contains no `private/` path. Preserve existing public README, architecture diagrams, and demo only when their asserted behavior remains true after the cutover.

## File Map

| Path | Action | Purpose |
|---|---|---|
| `pyproject.toml`, `uv.lock` | create | Package metadata, pinned runtime/test tooling, and test defaults. |
| `mcp_gateway/` | create | Generic application package ported selectively from `private/mcp-auth/app/`. |
| `mcp_gateway/config.py` | create | One-time fail-loud configuration, `*_FILE` secrets, placeholder and boundary validation. |
| `mcp_gateway/{main,oidc,introspect,tokens,token_page,pages,audit,registry,cli}.py` | create | ASGI factory, OIDC/token lifecycle, UI, audit, YAML registry, and token administration CLI. |
| `mcp_gateway/policy/{base,static_yaml}.py` | create | Policy contract and static YAML implementation. |
| `deploy/nginx/mcp-gateway.locations.conf` | create | Generic nginx auth-request contract. |
| `deploy/docker-compose.example.yml`, `Dockerfile`, `docker/` | create | Hardened deployment example and single-worker runtime. |
| `.env.example`, `examples/policy.yaml`, `examples/registry.yaml` | create | Safe operator configuration examples. |
| `demo/` | replace | End-to-end Keycloak/static-policy demo with no fixed operational secrets. |
| `tests/` | create | Consumer-observable regression coverage for each v0.1 contract. |
| `scripts/smoke-test.sh`, `Makefile` | create | Demo exerciser and repeatable local commands. |
| `.github/workflows/ci.yml`, `.gitleaks.toml`, `.gitignore`, `.dockerignore` | create/modify | CI, generic secret detection, and public-source build/release-boundary protections. |
| `README.md`, `docs/{deploy,client-compatibility}.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.github/{CODEOWNERS,ISSUE_TEMPLATE,pull_request_template.md}` | modify/create | Accurate public documentation and contribution/security policy. |

## Phases

| Phase | File | Dependency | Completion boundary |
|---|---|---|---|
| 00 | `phase-00-demo-oidc-contract.md` | none | Keycloak-only endpoint, strict-client, network, secret-bootstrap, and restart contract is executable and documented. |
| 01 | `phase-01-core-gateway.md` | Phase 00 | Generic package fulfills H1, H5, and H6 with OIDC, static policy, token lifecycle, registry, and CLI. |
| 02 | `phase-02-edge-deployment.md` | Phase 01 | nginx/deployment contract fulfills C1, H2, and H3. |
| 03 | `phase-03-demo-release.md` | Phase 02 | Demo, docs, CI, and public-release scan prove v0.1 is publishable.

## Cross-Phase Invariants

- All startup configuration errors name only the key/path, never a secret value.
- No response body, log entry, audit record, generated client configuration, or committed file contains an upstream token or personal-token plaintext after issuance.
- The only positive introspection response headers are `X-MCP-Gateway-User` and, for `kind: mcp`, `X-MCP-Gateway-Upstream-Token`.
- Deny and policy-unavailable paths fail closed; a policy parse or registry validation error aborts boot.
- Test fixtures use `gateway.example.com`, RFC 5737 documentation IP ranges, and `alice`/`bob`; all public prose and code comments are English.
- nginx clears client-supplied `X-MCP-Gateway-Server`, `X-MCP-Gateway-User`, and `X-MCP-Gateway-Upstream-Token` before setting any gateway-derived upstream values.
- Gateway public routes default-deny: nginx proxies only `/auth/` after clearing gateway-control request headers and hiding all gateway-control response headers; every other gateway path and method, including encoded or slash variants of introspection, returns 404 without reaching the application.
- Each upstream has its own `internal: true` network shared only with nginx; no two upstream services share a network.
- Runtime secrets use distinct read-only service-scoped mounts: Keycloak bootstrap (demo only), OIDC client, gateway session, and each upstream token are never co-mounted unless a service needs that exact file.
- The production deployment example uses an external HTTPS identity provider (`https://idp.example.com`): it contains no Keycloak service, and only the gateway joins a dedicated non-internal `idp-egress` network for OIDC back-channel calls. Compose Keycloak is demo-only (`demo/`, Phase 03).
- Production ingress terminates TLS before any personal bearer token or session cookie crosses a network; plain HTTP is permitted only for the loopback-bound demo and must be labeled insecure.

## Deferred Work

| Release | Blocked by | Explicitly excluded from v0.1 |
|---|---|---|
| v0.2 | v0.1 release and static-policy production verification | Keycloak Admin API role/group lookup, policy cache, rate limit, configurable audit retention. |
| v0.3 | v0.2 architecture/contract review | OpenFGA backend and templates, CSP, GHCR multi-arch images, SBOM, provenance. |

## Completion Criteria

1. A clean clone runs `uv sync --frozen`, the complete test suite, and the Compose demo without external internal-network dependencies.
2. A real browser completes the configured Keycloak OIDC flow; `alice` receives a token and can access `echo`, while `bob` receives 403.
3. The smoke suite observes 401, 403, 200 token exchange, HTTP API credential stripping, health endpoint hygiene, token revoke, and unauthorized introspection rejection.
4. CI runs ruff, socket-disabled pytest, generic secret detection, dependency CVE audit against the frozen lock, Docker build, Critical/High container-image scan, and the Compose smoke flow; all Critical/High audit findings block release.
5. The release scan passes tree, reachable history, commit metadata, image labels, and generated artifacts before any public push.
