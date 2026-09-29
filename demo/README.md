# Demo: token exchange behind nginx

A small, runnable version of the gateway's core. It has no OIDC sign-in and no
web UI: you issue tokens from the command line. Everything else works the way
the full gateway does:

- nginx asks the gateway about every request (`auth_request`),
- the gateway checks the personal token and the policy,
- nginx swaps the personal token for the upstream's own static token.

| File | Role |
|---|---|
| [`gateway.py`](gateway.py) | The `/introspect` endpoint, the token store (SHA-256 hashes in SQLite) and a small CLI |
| [`mock_mcp.py`](mock_mcp.py) | A stand-in MCP server that accepts one shared static token and knows nothing about the gateway |
| [`nginx.conf`](nginx.conf), [`protect.conf`](protect.conf) | The `auth_request` wiring |
| [`policy.yaml`](policy.yaml) | Who may use which server |

## Run it

Requires Docker with Compose v2.

```sh
cd demo
# The upstream's static token. Create the file before `up`: if it is missing,
# Docker creates a directory in its place.
python3 -c "import secrets; print(secrets.token_hex(32))" > echo_token
docker compose up -d --build
```

Issue a personal token for `alice`, who may use `echo` but not `echo2`:

```sh
TOKEN=$(docker compose exec -T gateway python gateway.py issue alice laptop)
```

## Try it

```sh
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize"}'

# 200: nginx swapped alice's token for the upstream's static token.
# The upstream reports "caller": "alice".
curl -s localhost:8080/echo/mcp -H "Authorization: Bearer $TOKEN" -d "$INIT"

# 403: alice is not allowed on echo2, although it is the same upstream.
curl -s localhost:8080/echo2/mcp -H "Authorization: Bearer $TOKEN" -d "$INIT"

# 401: no token.
curl -s localhost:8080/echo/mcp -d "$INIT"

# The health check skips auth, so nginx strips Authorization:
# "received_authorization": false.
curl -s localhost:8080/echo/healthz -H "Authorization: Bearer $TOKEN"

# 403 forbidden_caller: another container on the same network holds a valid
# token and calls the gateway directly. Only nginx may do that.
docker compose exec -T echo python -c "
import urllib.request, sys
req = urllib.request.Request('http://gateway:8000/introspect',
    headers={'Authorization': 'Bearer $TOKEN', 'X-MCP-Gateway-Server': 'echo'})
try: urllib.request.urlopen(req)
except Exception as e: print(e)"

# Revoke, then the first call returns 401.
docker compose exec -T gateway python gateway.py revoke alice laptop
```

Clean up with `docker compose down -v`.

## What the demo leaves out

- **Sign-in.** The full gateway issues tokens after OIDC sign-in (Keycloak is
  the reference) and prints ready-made client config.
- **Policy backends.** The demo reads a YAML file once at start. The full
  gateway also supports Keycloak roles and groups, and OpenFGA, with a
  short-lived decision cache and fail-closed behaviour.
- **Audit.** The full gateway writes one audit line per request.
