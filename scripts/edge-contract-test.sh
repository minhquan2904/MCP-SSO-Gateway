#!/usr/bin/env bash
# Real nginx/gateway edge contract check. Run separately from pytest (which blocks sockets).
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in docker curl openssl python3; do
  command -v "$command" >/dev/null || { printf 'missing required command: %s\n' "$command" >&2; exit 1; }
done
work=$(mktemp -d)
project="mcp-edge-$$"
compose=(docker compose -p "$project" -f "$root/deploy/docker-compose.example.yml" -f "$work/override.yml")
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if ! "${compose[@]}" down --volumes --remove-orphans; then
    printf 'edge contract cleanup failed: project=%s fixtures=%s (retained)\n' "$project" "$work" >&2
    if (( result == 0 )); then result=1; fi
  elif ! rm -rf -- "$work"; then
    printf 'edge contract fixture removal failed: project=%s fixtures=%s\n' "$project" "$work" >&2
    if (( result == 0 )); then result=1; fi
  elif (( result == 0 )); then
    printf 'edge contract passed (isolated Docker stack and fixtures removed)\n'
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf 'edge contract failed: %s\n' "$*" >&2; exit 1; }
mkdir -p "$work"/{oidc-client,gateway-session,echo-token,tls,discovery,mock}
# Docker mounts child paths directly; host users must not traverse this root.
chmod 0700 "$work"
chmod 0755 "$work"/{oidc-client,gateway-session,echo-token,tls,discovery,mock}
openssl rand -hex 32 > "$work/oidc-client/client-secret"
openssl rand -hex 32 > "$work/gateway-session/session-secret"
openssl rand -hex 32 > "$work/echo-token/token"
chmod 0644 "$work"/{oidc-client/client-secret,gateway-session/session-secret,echo-token/token}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=gateway.example.com' \
  -addext 'subjectAltName=DNS:gateway.example.com' \
  -keyout "$work/tls/tls.key" -out "$work/tls/tls.crt" >/dev/null 2>&1
chmod 0644 "$work/tls/tls.key" "$work/tls/tls.crt"
cat > "$work/discovery/metadata.json" <<'JSON'
{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","jwks_uri":"https://idp.example.com/jwks"}
JSON
# Extend the public demo mock without changing its token, health or JSON behavior.
cat > "$work/mock/observable_mock.py" <<'PY'
from http.server import ThreadingHTTPServer

from mock_mcp import Handler, PORT


class ObservableHandler(Handler):
    def _headers(self):
        return {
            **super()._headers(),
            "x_mcp_gateway_server": self.headers.get("X-MCP-Gateway-Server"),
            "x_mcp_gateway_original_uri": self.headers.get("X-MCP-Gateway-Original-URI"),
        }


ThreadingHTTPServer(("0.0.0.0", PORT), ObservableHandler).serve_forever()
PY
chmod 0644 "$work/mock/observable_mock.py"
# Only this disposable override uses an HTTP discovery fixture. It preserves
# the production issuer, networks, TLS ingress, secrets, registry and policy.
cat > "$work/override.yml" <<YAML
services:
  idp-fixture:
    image: python:3.12.11-slim-bookworm
    command: ["python", "-m", "http.server", "8000", "--directory", "/fixture"]
    volumes: ["$work/discovery:/fixture:ro"]
    networks: [idp-egress]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/metadata.json', timeout=2)"]
      interval: 2s
      timeout: 2s
      retries: 20
  gateway:
    environment:
      MCP_GATEWAY_OIDC_DISCOVERY_URL: http://idp-fixture:8000/metadata.json
      MCP_GATEWAY_ALLOW_INSECURE_OIDC: "true"
    depends_on:
      idp-fixture: {condition: service_healthy}
  echo:
    command: ["python", "/app/observable_mock.py"]
    volumes: ["$work/mock/observable_mock.py:/app/observable_mock.py:ro"]
  status:
    command: ["python", "/app/observable_mock.py"]
    volumes: ["$work/mock/observable_mock.py:/app/observable_mock.py:ro"]
volumes:
  oidc-client:
    driver_opts: {type: none, o: bind, device: "$work/oidc-client"}
  gateway-session:
    driver_opts: {type: none, o: bind, device: "$work/gateway-session"}
  echo-token:
    driver_opts: {type: none, o: bind, device: "$work/echo-token"}
  nginx-tls:
    driver_opts: {type: none, o: bind, device: "$work/tls"}
YAML
"${compose[@]}" up --build -d --wait || fail 'isolated stack did not become healthy'
"${compose[@]}" exec -T nginx nginx -t >/dev/null || fail 'nginx config parse failed'
# The only published port is TLS on loopback. --resolve pins the public hostname
# without requiring DNS or exposing a container port on a public interface.
base='https://gateway.example.com:8443'
curl_edge() { curl --noproxy '*' --resolve 'gateway.example.com:8443:127.0.0.1' --path-as-is -ksS --max-time 10 "$@"; }
check_status() {
  local want=$1 actual
  shift
  rm -f -- "$work/body" "$work/headers"
  actual=$(curl_edge -o "$work/body" -D "$work/headers" -w '%{http_code}' "$base$1" "${@:2}")
  [[ "$actual" == "$want" ]] || fail "expected $want for $1, got $actual"
  if tr -d '\r' < "$work/headers" | grep -Eqi '^X-MCP-Gateway-(Server|Original-URI|User|Upstream-Token):'; then
    fail "gateway control header leaked on $1"
  fi
}
# Issue two real personal tokens in the production-shaped gateway. Alice can
# call both routes; bob can call echo only, hence status is a policy denial.
issue() {
  local output
  output=$("${compose[@]}" exec -T gateway mcp-gateway issue \
    --issuer https://idp.example.com --subject "$1" --label edge-contract)
  printf '%s\n' "$output" | sed -n 's/^token:    //p'
}
alice=$(issue alice)
bob=$(issue bob)
[[ -n "$alice" && -n "$bob" ]] || fail 'CLI did not issue test tokens'
identity=$(python3 -c 'import base64,hashlib; print(base64.urlsafe_b64encode(hashlib.sha256(b"https://idp.example.com\0alice").digest()).rstrip(b"=").decode())')

# A peer on idp-egress is not nginx, even with a valid token and correct pair.
peer=$("${compose[@]}" exec -T -e EDGE_TOKEN="$alice" idp-fixture python -c \
  'import os,urllib.error,urllib.request; r=urllib.request.Request("http://gateway:8000/introspect", headers={"Authorization":"Bearer "+os.environ["EDGE_TOKEN"],"X-MCP-Gateway-Server":"echo","X-MCP-Gateway-Original-URI":"/echo/mcp"});
try: urllib.request.urlopen(r, timeout=5)
except urllib.error.HTTPError as e: print(e.code)')
[[ "$peer" == 403 ]] || fail "non-nginx peer expected 403, got $peer"

# Raw HTTP from the nginx container supplies the trusted TCP peer. This is not
# a public route; it lets us observe the app's 404 and 503, which auth_request
# maps to public 503 because nginx accepts only 2xx, 401, or 403 subresponses.
internal() {
  local server=$1 path=$2 bearer=$3
  "${compose[@]}" exec -T -e EDGE_TOKEN="$bearer" -e EDGE_SERVER="$server" \
    -e EDGE_PATH="$path" nginx sh -c \
    'wget -S -q -O /dev/null -T 5 --header "Authorization: Bearer $EDGE_TOKEN" --header "X-MCP-Gateway-Server: $EDGE_SERVER" --header "X-MCP-Gateway-Original-URI: $EDGE_PATH" http://gateway:8000/introspect 2>&1 || true'
}
internal_status() {
  local want=$1 response=$2 status
  status=$(printf '%s\n' "$response" | sed -n 's/^ *HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' | head -n 1)
  [[ "$status" == "$want" ]] || fail "trusted introspection expected $want, got $status"
}
internal_status 404 "$(internal absent /echo/mcp "$alice")"
internal_status 403 "$(internal echo /status/ "$alice")" # URI mismatch before token read.
internal_status 403 "$(internal status-api /status/ "$bob")"
internal_status 200 "$(internal echo /echo/mcp "$alice")"

# All public spellings and methods are 404 and have no gateway control headers.
for path in /_authz /_authz/ /introspect /introspect/ //introspect /%69ntrospect '/introspect;x' /INTROSPECT; do
  for method in GET POST PUT HEAD DELETE OPTIONS PATCH; do
    if [[ "$method" == HEAD ]]; then verb=(--head); else verb=(-X "$method"); fi
    check_status 404 "$path" "${verb[@]}" -H "Authorization: Bearer $alice" \
      -H 'X-MCP-Gateway-Server: echo' -H 'X-MCP-Gateway-User: spoof'
  done
done
check_status 404 /healthz -H "Authorization: Bearer $alice"
check_status 404 /auth/token -X DELETE -H "Authorization: Bearer $alice"
check_status 404 '/auth/%2e%2e/introspect' -H "Authorization: Bearer $alice"
check_status 401 /echo/mcp -X POST -d '{}'
check_status 401 /echo/mcp -X POST -d '{}' -H 'Authorization: Bearer invalid'
check_status 403 /status/ -H "Authorization: Bearer $bob"
check_status 200 /echo/mcp -X POST -H "Authorization: Bearer $alice" \
  -H 'Content-Type: application/json' -H 'X-MCP-Gateway-Server: status-api' \
  -H 'X-MCP-Gateway-Original-URI: /status/' -H 'X-MCP-Gateway-User: spoof' \
  -H 'X-MCP-Gateway-Upstream-Token: spoof' -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
EDGE_IDENTITY="$identity" EDGE_TOKEN="$alice" EDGE_UPSTREAM="$(cat "$work/echo-token/token")" \
  python3 - "$work/body" <<'PY'
import json, os, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))["result"]
assert body["authorization"] == "Bearer " + os.environ["EDGE_UPSTREAM"]
assert body["authorization"] != "Bearer " + os.environ["EDGE_TOKEN"]
assert body["x_mcp_gateway_user"] == os.environ["EDGE_IDENTITY"]
assert body["x_mcp_gateway_upstream_token"] is None
assert body["x_mcp_gateway_server"] is None
assert body["x_mcp_gateway_original_uri"] is None
PY
check_status 200 /status/ -H "Authorization: Bearer $alice" \
  -H 'X-MCP-Gateway-Server: echo' -H 'X-MCP-Gateway-Original-URI: /echo/' \
  -H 'X-MCP-Gateway-User: spoof' -H 'X-MCP-Gateway-Upstream-Token: spoof'
EDGE_IDENTITY="$identity" python3 - "$work/body" <<'PY'
import json, os, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
assert body["authorization"] is None
assert body["x_mcp_gateway_user"] == os.environ["EDGE_IDENTITY"]
assert body["x_mcp_gateway_upstream_token"] is None
assert body["x_mcp_gateway_server"] is None
assert body["x_mcp_gateway_original_uri"] is None
PY
# Existing token path remains in the registry but becomes unreadable to uid 1000.
chmod 000 "$work/echo-token/token"
internal_status 503 "$(internal echo /echo/mcp "$alice")"
check_status 503 /echo/mcp -X POST -H "Authorization: Bearer $alice" -d '{}'
