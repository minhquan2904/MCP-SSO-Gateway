# 2026-09-30 — Phase 00 Keycloak probe

## What changed
- Completed the Keycloak-only OIDC probe topology with a dedicated `keycloak-probe` profile and an nginx public surface allowlisted to browser-required `mcp-demo` routes.
- Made bootstrap marker-aware: first initialization consumes the temporary bootstrap credential, while retained-volume recreation validates the marker and client secret without invoking the Admin API.
- Used an ephemeral, least-privilege master-realm cleanup service account to remove the temporary bootstrap administrator and its password material after client reconciliation.

## Why
- The probe establishes the public issuer and private discovery contract before the gateway exists, while keeping Keycloak administration and management endpoints off the public surface.

## Tradeoffs accepted
- Public token access is intentionally denied; browser routes are exposed only where required. Token, JWKS, discovery, and logout remain available from the identity-provider network as applicable.
- The imported realm stays non-secret; the confidential client is created at runtime from private secret volumes.

## Surprises
- Keycloak 26 canonical client representation omits the false `authorizationServices` field rather than serializing it.
- Disabled client-credentials access returns 401, which is the expected behavior for the reconciled client.

## Carry-forward
- `bash demo/probe/probe.sh` completed the fresh initialization, retained-volume recreate, and `down -v` cleanup lifecycle successfully; this is the Phase 00 runtime proof.
- Phase 01 consumes only the documented issuer/discovery fixture. Phase 00 makes no browser sign-in, callback, or personal-token claim.
