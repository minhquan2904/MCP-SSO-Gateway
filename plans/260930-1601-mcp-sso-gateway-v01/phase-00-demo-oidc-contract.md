---
status: completed
priority: P1
dependsOn: []
---

# Phase 00: Prove the Demo OIDC Contract

## Purpose

Prove the Keycloak endpoint and runtime-secret bootstrap contract before porting the application. This phase deliberately does not run the gateway, perform its callback, or issue a personal token; those require the package delivered in Phase 01.

## Files

| File | Action |
|---|---|
| `demo/keycloak-probe.compose.yaml` | create a Keycloak-only topology: nginx exposes a path-allowlisted public Keycloak prefix; Keycloak has no published port and persists its state on a private named volume |
| `demo/keycloak/realm.json` | create a realm with public, non-secret settings and demo users but no confidential-client secret |
| `demo/init-secrets.sh` | create distinct private named volumes for bootstrap admin, OIDC client, gateway session, and each upstream credential; each downstream service mounts only needed files read-only |
| `demo/keycloak-entrypoint.sh` | read bootstrap credential only while a persistent Keycloak-state marker is absent, then start Keycloak without storing credentials in tracked configuration |
| `demo/init-keycloak-client.sh` | run with `network_mode: service:keycloak` and no additional network endpoint; if the persistent initialized marker plus required client-secret file already exist, verify their ownership/permissions and exit success without Admin API or bootstrap-secret access; otherwise wait for local health, reconcile the confidential OIDC client through the Admin API with a validated expected `Host`, delete the temporary bootstrap administrator and password, then atomically write the marker |
| `demo/.env.example` | create safe demo operator inputs including explicit public issuer/base URL and private back-channel URL |
| `docs/deploy.md` | create topology diagram and endpoint explanation |

## Steps

1. Define the public issuer/base as a fixed nginx-proxied Keycloak prefix and a private gateway-to-Keycloak back-channel URL. nginx, gateway, and Keycloak join the identity-provider network; nginx alone exposes the public Keycloak prefix, and Keycloak never publishes a host port. Pin `KC_HOSTNAME` and `KC_HOSTNAME_ADMIN`; keep management endpoints private. Record the exact endpoint set and issuer string as the Phase 01 configuration fixture.
2. nginx public Keycloak routing is an allowlist for the demo realm's browser-needed authorization, logout, login-actions, and resource paths. It returns 404 for `/admin`, `master`-realm paths, Admin API paths, `/metrics`, `/health`, and every other Keycloak path. It overwrites `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`; it never forwards client-supplied variants.
3. Run `init-secrets` first. It creates random bootstrap-admin, OIDC-client, session, and upstream credentials in their separate untracked volumes. Keycloak starts only after this service succeeds. On first initialization only, its wrapper reads the bootstrap password. Persistent Keycloak state and an explicit initialization marker survive normal service restart/recreate; `docker compose down -v` intentionally resets both and creates new credentials.
4. Import a realm that contains only non-secret realm/users/client metadata. For a marker-absent first initialization, `init-keycloak-client` shares Keycloak's network namespace, waits for local health, obtains an Admin API token using the generated bootstrap credential, reconciles the confidential client, deletes/disables the temporary bootstrap administrator, removes its password file, and atomically writes the marker. This localhost Admin API access is the sole exception to public/private Admin denial and does not add any identity-provider network membership. Recreated initializers with the marker and secret present exit successfully without bootstrap credentials. Gateway/nginx must later depend on this initializer's successful completion.
5. Reconcile the client to exact callback and post-logout redirect URLs derived from the recorded public gateway base; enable confidential-client authentication, authorization-code flow, and PKCE S256; disable implicit flow, direct-access grants, service accounts, wildcard redirects, and wildcard web origins. Probe the client representation through the Admin API before Phase 01.
6. Configure Keycloak hostname/backchannel settings so browser authorization through nginx, container code exchange, JWKS retrieval, and logout use the recorded endpoints. Do not rely on `/etc/hosts`, an external DNS name, a private IP, or a fixed client secret.
7. Probe discovery, authorization endpoint redirect, token endpoint reachability, JWKS, and logout from the correct browser/container vantage points. Verify the tracked realm has no client secret and the generated confidential client is ready for authorization-code exchange once Phase 01 supplies the callback.

## Acceptance

- The browser reaches only nginx's path-allowlisted Keycloak browser routes without a Compose-only hostname; public `/admin`, `master`-realm/Admin API, `/metrics`, `/health`, and unlisted paths return 404. The gateway network reaches discovery/JWKS/token/logout without `localhost`, and Keycloak exposes no host port.
- Keycloak cannot start before runtime secrets exist; the client initializer cannot complete first initialization until Keycloak is healthy; a later gateway must depend on client-initializer success. A restart/recreate with retained named volumes does not recreate a bootstrap administrator, does not require bootstrap credentials, exits initializer successfully from the marker path, and leaves the reconciled client usable.
- The tracked realm contains no session secret, bootstrap password, OIDC client secret, or upstream token; after initialization, the temporary bootstrap administrator is absent/disabled and its password file is removed.
- Each service mounts only its declared secret volume: Keycloak receives bootstrap data only during first initialization; client initializer receives bootstrap/client files; gateway receives OIDC/session and only its required upstream token; upstreams receive only their own token.
- The reconciled client has only exact callback/post-logout URLs, client authentication, authorization-code flow, and PKCE S256; it has no implicit/direct-access/service-account flow or wildcard redirect/origin.

## Exit Gate

Record the accepted endpoint/bootstrap configuration in `docs/deploy.md`. Phase 01 implements the application against it; Phase 03 is the first phase allowed to claim a browser sign-in, callback, personal-token issuance, or `alice`/`bob` authorization result.
