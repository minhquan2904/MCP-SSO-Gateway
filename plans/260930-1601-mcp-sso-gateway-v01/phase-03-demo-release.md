---
status: in_progress
blockedBy:
  - release-owner out-of-band deny-pattern file (real release scan)
  - approved commit for fresh-clone exit gate and GitHub CI run
priority: P1
dependsOn:
  - phase-02-edge-deployment.md
---

# Phase 03: Replace the Demo and Publish v0.1 Evidence

## Purpose

Run the real `mcp_gateway` package through the full public demo, reconcile every user-facing claim with v0.1 scope, and make release verification repeatable before a public push.

## Files

| Path | Action | Required behavior |
|---|---|---|
| `demo/gateway.py` | remove | Eliminate the duplicate implementation; demo runs the packaged gateway image. |
| `demo/compose.yaml`, `demo/nginx.conf`, `demo/protect.conf`, `demo/mock_mcp.py` | replace | Reuses the Phase 02 network model and packaged gateway; composes Keycloak, generated runtime secrets, one MCP upstream, one HTTP API upstream, and nginx. |
| `demo/keycloak/realm.json`, `demo/init.*`, `demo/README.md` | create/modify | Safe fixture realm, one-shot secret bootstrap, and exact local workflow. |
| `scripts/smoke-test.sh`, `Makefile` | create | Exercise real services and expose repeatable developer/release commands. |
| `README.md`, `docs/deploy.md`, `docs/client-compatibility.md`, `SECURITY.md` | modify/create | State only shipped behavior and security assumptions. |
| `CONTRIBUTING.md`, `CHANGELOG.md`, `.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/*`, `.github/pull_request_template.md` | create | Establish public contribution/release policy. |
| `.github/workflows/ci.yml`, `.gitleaks.toml`, `.gitignore`, `.dockerignore` | create/modify | CI, generic secret detection, and source/build-boundary protection. |

## Steps

1. Replace `demo/gateway.py` with the packaged application image. Keep `alice` as a static-policy allow fixture and `bob` as a deny fixture; add a no-credential HTTP API fixture so both nginx branches run in the real demo.
2. Use Phase 00's accepted Keycloak configuration and runtime init service. The demo must inherit Phase 02's authz/identity-provider/per-upstream internal network memberships, caller-hostname allowlist, service-scoped secret mounts, no-published-gateway/upstream/Keycloak-port rule, and compose-hardening test coverage. Bind nginx to `127.0.0.1` only and label HTTP-cookie behavior demo-only.
3. Write the smoke script to wait for Compose health, use the supported CLI or OIDC session path to create an authorized token, and observe: health header stripping; missing/bad token 401; static-policy deny 403; MCP token exchange 200; HTTP API authorization stripping 200; spoofed gateway headers stripped; all public introspection paths/methods 404 with no gateway headers; direct gateway-network introspection denial; revoke then 401. Remove generated plaintext tokens and volumes at script teardown.
4. Update README and diagrams only where behavior changed. v0.1 documentation must say static YAML policy only; Keycloak roles/groups and OpenFGA are future releases. State restart-to-apply policy semantics, SQLite single-worker restriction, nginx-only ingress, secret-file mounting, upstream-header trust boundary, demo HTTP caveat, PAT mode rather than MCP OAuth authorization-server discovery, and that production TLS termination is mandatory for all gateway ingress carrying sessions or bearer tokens.
5. Add CI jobs for `uv sync --frozen`, ruff, socket-disabled pytest, gitleaks, frozen-lock dependency CVE audit, Docker build, Critical/High container-image scan, and Compose smoke. Dependency/image audit findings at Critical/High block release; CI fixture values must not require external networks apart from public dependency/image fetches.
6. Add a pre-push release scan that checks working tree, reachable history, commit metadata, generated artifacts, image labels, and tracked documentation for sensitive internal references. Internal-reference deny patterns must be supplied only out-of-band (for example, an untracked local file or protected CI secret), never committed in `.gitleaks.toml`, CI, or any tracked artifact; the release gate verifies that all tracked files, including scanner configuration, scan clean. Keep generic public secret detection in tracked configuration and test scanner canaries before trusting a zero-result report.
7. Create the v0.1 changelog entry and contribution/security templates. Do not publish an image, create a tag, or push a release in this phase; that is an explicit release-owner action after the gates pass.

## Acceptance

- A clean clone can run the documented setup, `uv sync --frozen`, all tests, `docker compose -f demo/compose.yaml up`, browser OIDC sign-in, and `scripts/smoke-test.sh` without private hosts, sibling repositories, or manually supplied secrets.
- Browser verification shows authorized `alice` can issue one token and use the MCP route; `bob` cannot issue a usable token and receives the documented denial.
- Root README, demo README, deploy/client/security documentation, and diagrams contain no claim that v0.2/v0.3 functionality already exists.
- CI executes all six required gates. The release scan returns zero sensitive-reference matches and its canaries prove every scanner expression actually matches.

## Exit Gate

Run the release gates from a fresh clone, retain their raw output as release evidence, then obtain the release owner's explicit instruction before any public tag or push.

## Status (2026-10-01)

Implemented and verified on the working tree: packaged-gateway demo, smoke, edge contract, Phase 00 probe, frozen sync, Ruff, socket-disabled pytest, Docker build, Trivy Critical/High (0), pip-audit (clean), actionlint, generic Gitleaks history and publishable tree, release-scan self-test (deny engine + Gitleaks PAT canary), and the full-scan path with a synthetic deny file (including staged-index detection). Browser: alice issued a token and used `/echo/` (200), revoke then 401; bob saw the no-access page (HTTP 200) with no issue form. Bob's 403 is proven by `test_no_grant_user_sees_no_catalog_and_cannot_issue` (valid-CSRF forged issuance POST returns 403 and stores no token; fails when the grant check is removed) and by smoke at the edge.

Open exit-gate items: real out-of-band deny-pattern scan, fresh-clone run of a committed candidate, and a GitHub Actions run. No commit, tag, push, or image publish has occurred.
