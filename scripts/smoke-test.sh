#!/usr/bin/env bash
# End-to-end smoke test for the loopback HTTP demo (demo/compose.yaml).
#
# Runs in an isolated Compose project, so it never touches a demo started with
# the default project name; it still needs host port 127.0.0.1:8080 free.
# Personal and upstream tokens are only ever stored in a private temporary
# directory and passed to curl through header files or to containers through
# environment variables; they are never printed or placed on a command line.
# The stack, its volumes, and the temporary directory are removed on every exit.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in docker curl python3; do
  command -v "$command" >/dev/null || { printf 'missing required command: %s\n' "$command" >&2; exit 1; }
done

readonly project=mcp-sso-gateway-smoke
readonly base=http://localhost:8080
readonly issuer=http://localhost:8080/idp/realms/mcp-demo
readonly alice=11111111-1111-4111-8111-111111111111
readonly bob=22222222-2222-4222-8222-222222222222
compose=(docker compose -p "$project" -f "$root/demo/compose.yaml")

umask 077
work=$(mktemp -d)
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if ! "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
    printf 'smoke cleanup failed: run "docker compose -p %s -f demo/compose.yaml down -v"\n' "$project" >&2
    if (( result == 0 )); then result=1; fi
  fi
  rm -rf -- "$work" || { printf 'smoke cleanup could not remove %s\n' "$work" >&2; result=1; }
  if (( result == 0 )); then
    printf 'smoke test passed (stack, volumes, and generated tokens removed)\n'
  else
    printf 'smoke test failed (stack, volumes, and generated tokens removed)\n' >&2
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { printf 'smoke failed: %s\n' "$*" >&2; exit 1; }

# request EXPECTED PATH [curl args...]: body -> $work/body, headers -> $work/headers.
# Every public response must be free of gateway control headers.
request() {
  local want=$1 path=$2 actual
  shift 2
  rm -f -- "$work/body" "$work/headers"
  actual=$(curl --noproxy '*' --path-as-is -sS --max-time 15 -o "$work/body" -D "$work/headers" \
    -w '%{http_code}' "$@" "$base$path") || fail "request to $path did not complete"
  [[ "$actual" == "$want" ]] || fail "expected HTTP $want for $path, got $actual"
  if tr -d '\r' <"$work/headers" | grep -Eqi '^X-MCP-Gateway-[A-Za-z-]*:'; then
    fail "gateway control header leaked on $path"
  fi
}

# json_check PYTHON_EXPR: evaluates against `body` (parsed $work/body) and `env`.
json_check() {
  SMOKE_CHECK=$1 python3 - "$work/body" <<'PY' || fail "response assertion failed: $1"
import json, os, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
env = os.environ
if not eval(os.environ["SMOKE_CHECK"]):
    raise SystemExit(1)
PY
}

# Writes an Authorization header file for curl `-H @file`.
bearer_file() { printf 'Authorization: Bearer %s\n' "$(cat -- "$1")" >"$2"; }

printf 'starting demo stack (project %s)\n' "$project"
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up --build -d || fail 'demo stack did not start'

# One-shot initializers exit, so poll long-running service health instead of
# relying on `up --wait`. nginx starts only after its dependencies are healthy.
ready=
for _ in $(seq 1 150); do
  ready=1
  for service in gateway echo status nginx; do
    id=$("${compose[@]}" ps -q "$service" 2>/dev/null || true)
    if [[ -z "$id" || $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id" 2>/dev/null) != healthy ]]; then
      ready=
      break
    fi
  done
  [[ -n "$ready" ]] && break
  sleep 2
done
[[ -n "$ready" ]] || { "${compose[@]}" ps -a >&2 || true; fail 'demo services did not become healthy'; }

printf 'checking public health, sign-in routing, and the Keycloak allowlist\n'
request 200 /echo/healthz -H 'Authorization: Bearer spoof' -H 'X-MCP-Gateway-User: spoof' \
  -H 'X-MCP-Gateway-Upstream-Token: spoof' -H 'X-MCP-Gateway-Server: status' \
  -H 'X-MCP-Gateway-Original-URI: /status/'
json_check 'body["ok"] is True and all(body[key] is None for key in ("authorization", "x_mcp_gateway_user", "x_mcp_gateway_upstream_token", "x_mcp_gateway_server", "x_mcp_gateway_original_uri"))'
request 302 /auth
location=$(tr -d '\r' <"$work/headers" | sed -n 's/^[Ll]ocation: //p')
[[ "$location" == "$issuer/protocol/openid-connect/auth?"* ]] || fail '/auth did not redirect to the demo issuer'
request 200 "${location#"$base"}"
request 200 /idp/realms/mcp-demo/.well-known/openid-configuration
for path in /idp/admin/ /idp/realms/master/ /idp/realms/mcp-demo/protocol/openid-connect/token /healthz /auth/%2e%2e/introspect; do
  request 404 "$path"
done

printf 'issuing fixture tokens\n'
"${compose[@]}" exec -T gateway mcp-gateway issue --issuer "$issuer" --subject "$alice" --label smoke \
  | sed -n 's/^token:    //p' >"$work/alice-token"
[[ -s "$work/alice-token" ]] || fail 'CLI did not issue an alice token'
bearer_file "$work/alice-token" "$work/alice-auth"
if "${compose[@]}" exec -T gateway mcp-gateway issue --issuer "$issuer" --subject "$bob" --label smoke \
  >"$work/bob-cli" 2>/dev/null; then
  fail 'CLI issued a token to bob, who has no policy grant'
fi
grep -q '^token:' "$work/bob-cli" && fail 'CLI printed a token for bob'
# Simulate a stale bob token (for example, issued before a grant was removed)
# by writing straight to the token store; the edge must still deny it.
"${compose[@]}" exec -T gateway python -c \
  'import sys; from mcp_gateway.tokens import TokenStore; print(TokenStore("/data/mcp-gateway.sqlite3").issue(sys.argv[1], sys.argv[2], "smoke-deny", 3600).token)' \
  "$issuer" "$bob" >"$work/bob-token"
[[ -s "$work/bob-token" ]] || fail 'could not store the bob deny fixture'
bearer_file "$work/bob-token" "$work/bob-auth"
"${compose[@]}" exec -T echo cat /run/secrets/echo-token/token >"$work/echo-upstream-token"
[[ -s "$work/echo-upstream-token" ]] || fail 'could not read the echo upstream token'
identity=$(python3 -c 'import base64, hashlib, sys; print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode() + b"\0" + sys.argv[2].encode()).digest()).rstrip(b"=").decode())' "$issuer" "$alice")
export SMOKE_IDENTITY=$identity SMOKE_WORK=$work

printf 'checking 401 and 403 responses\n'
mcp_body='{"jsonrpc":"2.0","id":1,"method":"initialize"}'
for path in /echo/mcp /status/; do
  request 401 "$path"
  json_check 'body["error"] == "unauthorized"'
  request 401 "$path" -H 'Authorization: Bearer invalid'
  json_check 'body["error"] == "unauthorized"'
  request 403 "$path" -H @"$work/bob-auth"
  json_check 'body["error"] == "forbidden"'
done
request 401 /echo/mcp -X POST -H 'Content-Type: application/json' -d "$mcp_body"
tr -d '\r' <"$work/headers" | grep -qi '^Content-Type: application/json' || fail '401 is not JSON'

printf 'checking MCP token exchange and HTTP API credential stripping\n'
spoof=(-H 'X-MCP-Gateway-User: spoof' -H 'X-MCP-Gateway-Upstream-Token: spoof'
  -H 'X-MCP-Gateway-Server: status' -H 'X-MCP-Gateway-Original-URI: /status/')
request 200 /echo/mcp -X POST -H @"$work/alice-auth" -H 'Content-Type: application/json' "${spoof[@]}" -d "$mcp_body"
json_check 'body["result"]["authorization"] == "Bearer " + open(env["SMOKE_WORK"] + "/echo-upstream-token").read().strip()'
json_check 'body["result"]["authorization"] != "Bearer " + open(env["SMOKE_WORK"] + "/alice-token").read().strip()'
json_check 'body["result"]["x_mcp_gateway_user"] == env["SMOKE_IDENTITY"]'
json_check 'all(body["result"][key] is None for key in ("x_mcp_gateway_upstream_token", "x_mcp_gateway_server", "x_mcp_gateway_original_uri"))'
spoof=(-H 'X-MCP-Gateway-User: spoof' -H 'X-MCP-Gateway-Upstream-Token: spoof'
  -H 'X-MCP-Gateway-Server: echo' -H 'X-MCP-Gateway-Original-URI: /echo/')
request 200 /status/ -H @"$work/alice-auth" "${spoof[@]}"
json_check 'body["authorization"] is None and body["x_mcp_gateway_user"] == env["SMOKE_IDENTITY"]'
json_check 'all(body[key] is None for key in ("x_mcp_gateway_upstream_token", "x_mcp_gateway_server", "x_mcp_gateway_original_uri"))'

printf 'checking that every public introspection spelling is 404\n'
for path in /_authz /_authz/ /introspect /introspect/ //introspect /%69ntrospect '/introspect;x' /INTROSPECT; do
  for method in GET POST PUT HEAD DELETE OPTIONS PATCH; do
    if [[ "$method" == HEAD ]]; then verb=(--head); else verb=(-X "$method"); fi
    request 404 "$path" "${verb[@]}" -H @"$work/alice-auth" \
      -H 'X-MCP-Gateway-Server: echo' -H 'X-MCP-Gateway-Original-URI: /echo/mcp'
  done
done

printf 'checking that only nginx may call introspection\n'
# Keycloak shares the identity-provider network with the gateway but is not an
# allowed caller; it must be refused before the token is looked up.
direct=$(SMOKE_TOKEN=$(cat -- "$work/alice-token") "${compose[@]}" exec -T -e SMOKE_TOKEN keycloak bash -c \
  'exec 3<>/dev/tcp/gateway/8000; printf "GET /introspect HTTP/1.0\r\nHost: gateway\r\nAuthorization: Bearer %s\r\nX-MCP-Gateway-Server: echo\r\nX-MCP-Gateway-Original-URI: /echo/mcp\r\n\r\n" "$SMOKE_TOKEN" >&3; IFS= read -r status_line <&3; printf "%s\n" "$status_line"') \
  || fail 'non-nginx introspection probe did not complete'
[[ "$direct" == *' 403 '* ]] || fail 'non-nginx introspection peer was not refused with 403'
for upstream in echo status; do
  if "${compose[@]}" exec -T "$upstream" python -c \
    "import socket; socket.create_connection(('gateway', 8000), 2)" >/dev/null 2>&1; then
    fail "$upstream upstream can reach the gateway"
  fi
done

printf 'checking revocation\n'
"${compose[@]}" exec -T gateway mcp-gateway revoke --issuer "$issuer" --subject "$alice" --label smoke >/dev/null
request 401 /echo/mcp -X POST -H @"$work/alice-auth" -H 'Content-Type: application/json' -d "$mcp_body"
request 401 /status/ -H @"$work/alice-auth"
