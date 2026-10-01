# Contributing

## Scope and setup

v0.1 ships a static YAML registry and policy, PAT-based clients, an OIDC browser
login, one SQLite-backed gateway worker, and nginx-only ingress. Keycloak
roles/groups, OpenFGA, policy caching, and MCP OAuth authorization-server
discovery are not implemented. Keep documentation, tests, and code aligned with
that boundary.

From a clean clone, install the frozen dependencies:

```sh
uv sync --frozen
```

Run the checks relevant to your change:

```sh
uv run --frozen ruff check .
uv run --frozen pytest --disable-socket --allow-unix-socket
scripts/smoke-test.sh
```

The smoke script uses its own Compose project, needs port 8080 free, and removes
its volumes on exit. Stop a manual demo before running it. Production deployment uses
an external HTTPS IdP; see [deployment guidance](docs/deploy.md).

## Pull requests

- Describe observable behavior, security-boundary effects, and verification.
- Do not commit secrets, live credentials, private hostnames, or private patterns.
  Use `gateway.example.com`, `idp.example.com`, demo localhost, fixture users
  `alice`/`bob`, and RFC 5737 addresses for examples.
- Keep production TLS, nginx-only ingress, service-scoped file secrets, and
  single-worker SQLite assumptions intact. Registry/policy edits require restart.
- CI (`.github/workflows/ci.yml`) runs `lint-test` (`uv sync --frozen`, Ruff,
  socket-disabled pytest), `gitleaks`, `dependency-audit` (pip-audit over
  `uv export --frozen --all-groups`; any known vulnerability blocks), `image`
  (Docker build plus Trivy Critical/High scan), `compose-smoke`, and
  `release-scan`. CI never pushes, tags, or publishes an image.

## Release handoff

Before an authorized public push, build a local `mcp-sso-gateway:*` release
candidate image and supply an out-of-band deny file outside the repository.
Each active line is `<python regex><TAB><synthetic sample that must match>`;
blank lines and `#` comments are ignored. Never commit, image, or attach that file.
The full scan requires git, Docker, and Gitleaks:

```sh
MCP_GATEWAY_DENY_PATTERNS_FILE=/path/outside/repo/deny.tsv scripts/release-scan.sh
```

It proves each expression matches its sample, then scans tracked and untracked
non-ignored files, staged index blobs, reachable Git objects and metadata,
`dist/`, `build/`, `.release-scan/artifacts/` (plus optional
`MCP_GATEWAY_RELEASE_ARTIFACTS_DIR`), and local image labels, and runs Gitleaks.
`make release-scan` runs the full scan. `make release-scan-selftest` (or
`scripts/release-scan.sh --self-test`) proves the deny-expression engine and the
Gitleaks PAT rule with synthetic canaries and requires Gitleaks; with a deny
file it also checks each line's sample, but it is not a full scan. In CI, the
full scan runs only when protected
secret `MCP_GATEWAY_DENY_PATTERNS` is set. Retain raw release-gate output and
obtain explicit release-owner approval before any public tag or push.
