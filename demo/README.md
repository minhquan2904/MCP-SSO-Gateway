# MCP SSO Gateway demo

This loopback-only HTTP demo runs the packaged gateway, Keycloak, nginx, an MCP
upstream, and a no-credential HTTP API upstream. It is intentionally insecure:
production ingress MUST terminate TLS before cookies or bearer tokens cross a
network.

From the repository root:

```sh
docker compose -f demo/compose.yaml up --build -d
```

Open `http://localhost:8080/auth` and sign in as `alice` with
`alice-demo-password`. The `/auth/token` page issues a PAT shown once. Use it
as `Authorization: Bearer <token>` against `/echo/mcp` or `/status/`.
`bob` / `bob-demo-password` can sign in but cannot issue a PAT: the static
policy grants no server access. The demo's local `roles` are YAML grant labels,
not Keycloak roles/groups. Keycloak and all gateway/upstream ports remain private;
only nginx binds `127.0.0.1:8080`.

When finished, remove the demo's containers and generated secret/state volumes:

```sh
docker compose -f demo/compose.yaml down -v --remove-orphans
```

For repeatable edge assertions instead of the manual browser flow, run
`scripts/smoke-test.sh` from the repository root. It builds/starts the demo,
issues an alice token with the packaged CLI, checks 401/403/200 responses,
header stripping, introspection denial and revocation, then tears down volumes.
It uses its own Compose project but needs port 8080 free, so stop a manual demo first.

The registry and policy load once at gateway startup. Restart the gateway after
editing `registry.yaml` or `policy.yaml`. The tracked demo passwords are public
fixtures; never deploy them outside this loopback-only, insecure HTTP demo.
