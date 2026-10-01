---
status: completed
priority: P1
dependsOn:
  - phase-00-demo-oidc-contract.md
---

# Phase 01: Build the Generic Core Gateway

## Purpose

Port only the reusable behavior from `private/mcp-auth/app/` into `mcp_gateway/`; replace all organization-specific names, identity transformations, fixed registry entries, policy providers, and UI text. This phase owns the public Python contract before nginx/deployment wiring.

## Files and Source Mapping

| Target | Reference source | Required change |
|---|---|---|
| `mcp_gateway/config.py` | `private/mcp-auth/app/config.py` | Remove `ZO_*`, claim-role maps, and tuple provider choices. Add gateway-prefixed paths/TTLs, OIDC discovery override, insecure-demo flag, and validated `*_FILE` secrets. |
| `mcp_gateway/oidc.py` | `private/mcp-auth/app/oidc.py` | Use provider name `oidc`; validate issuer; require `sub`; retain PKCE and ID-token validation; do not normalize subjects. |
| `mcp_gateway/tokens.py` | `private/mcp-auth/app/tokens.py` | Persist `issuer`, `subject`, and full-digest `identity_id` separately; generate/check the documented `mcpgw_` token format; retain hash-only storage, expiry, revoke, and label uniqueness. |
| `mcp_gateway/policy/{base,static_yaml}.py` | `private/mcp-auth/app/policy/{base,static_yaml}.py` | Load the locked role/member grammar, resolve only declared bare registry names, and remove object-prefix coupling. |
| `mcp_gateway/registry.py` | `private/mcp-auth/app/registry.py` | Load routing/upstream metadata only from YAML at boot: unique names/paths, safe names, canonical paths, allowed kinds, and absolute readable token-file paths. |
| `mcp_gateway/{main,introspect}.py` | `private/mcp-auth/app/{main,introspect}.py` | Use app factory; enforce peer plus original-URI/path binding and 401/403/404/503 semantics; retain no-token logging invariant. |
| `mcp_gateway/{token_page,pages}.py` | `private/mcp-auth/app/{token_page,pages}.py` | Translate all output to English, use neutral local font/color tokens, scope a uniquely named session cookie to `/auth`, format time from configuration, and render only allowed servers. |
| `mcp_gateway/audit.py` | `private/mcp-auth/app/audit.py` | Preserve JSONL rotation/no-token behavior; configure max bytes and remove internal context. |
| `mcp_gateway/cli.py` | new, using token store and static policy | Implement `issue --issuer --subject --label`, `revoke`, and `list`; issue derives the canonical identity and refuses an identity with no allowed declared server. |
| `pyproject.toml`, `uv.lock`, `Dockerfile`, `docker/` | `private/mcp-auth/*` | Rename package/runtime references, remove proxy/internal comments, and preserve one-worker SQLite deployment invariant. |

## Steps

1. Add `pyproject.toml` and the `mcp_gateway` package skeleton. Use the app factory as the only runtime construction point so imports do not require environment variables or secret files.
2. Implement immutable configuration loading and a production-safe `.env.example`. Require at least 32 non-whitespace UTF-8 session-secret bytes; reject placeholders, invalid URL/scheme combinations, an empty caller-hostname allowlist, any direct IP/CIDR allowlist value, invalid registry/token paths, and insecure discovery unless the explicit demo-only flag is enabled.
3. Implement the locked identity representation. Validate OIDC `iss` exactly against configured issuer; persist issuer, subject, and full-digest `identity_id`; use only `identity_id` in audit/upstream headers; treat username claims as escaped display data. Migrate SQLite schema through `PRAGMA user_version` and make the initial public schema fresh-install safe.
4. Implement registry and static YAML policy together using the locked separate-file grammar. A malformed policy, role grant to an undeclared server, duplicate server/path, unsafe name, or `kind: mcp` without an upstream-token file must terminate startup. `kind: http_api` remains authorization-protected but can never return an upstream token.
5. Implement OIDC login, logout, token issue/list/revoke, CSRF-protected token forms, and generated Claude Code/Desktop configuration. Generated `.mcp.json` uses `${MCP_GATEWAY_TOKEN}` only; it never embeds plaintext. Limit plaintext issue output to the one-time HTML response and CLI stdout.
6. Implement introspection and audit. Parse Bearer tokens strictly, reject a non-nginx TCP peer before token lookup, reject any original-URI/server/path mismatch, and emit the two response headers only on a successful allowed request. Preserve explicit 503 for policy/unreadable upstream-secret failure.
7. Add consumer-observable tests while each seam is implemented. Port legacy test intent, not legacy names or internal fixtures.

## Acceptance

- `pytest` proves issuer/subject collisions cannot authorize another issuer, invalid OIDC metadata is rejected, token checksum tampering is rejected, expiry/revoke works, and no token plaintext is persisted.
- Tests prove YAML registry and policy startup failures, server/path/name validation, `mcp` token-file requirement, HTTP API no-upstream-token behavior, and CLI issue/revoke/list behavior including same-subject/different-issuer identities and unauthorized issue refusal.
- Tests prove peer denial happens before token lookup, malformed authorization is 401, denied policy is 403, missing server is 404, and unavailable policy/upstream secret is 503.
- HTML/client-config tests assert escaped output, `${MCP_GATEWAY_TOKEN}` usage, scoped cookie attributes, and no plaintext token after its one-time issuance response.

## Exit Gate

All tests use only generic English fixtures and public documentation domains. No imports, package metadata, runtime command, config key, header, UI string, or test fixture retains a legacy compatibility path.
