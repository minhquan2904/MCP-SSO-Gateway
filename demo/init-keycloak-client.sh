#!/bin/bash
set -euo pipefail

readonly realm=mcp-demo
readonly client_id=mcp-gateway
readonly marker=/opt/keycloak/data/mcp-gateway-client-initialized
readonly bootstrap_password_file=/run/secrets/bootstrap-admin/password
readonly client_secret_file=/run/secrets/oidc-client/client-secret
readonly public_base=${MCP_GATEWAY_PUBLIC_BASE_URL:-}
readonly admin_server=http://localhost:8080/idp
readonly callback_url="${public_base}/auth/callback"
readonly logout_url="${public_base}/auth/logged-out"
readonly bootstrap_absent_message="verified temporary bootstrap administrator is absent"

require_secure_file() {
    local path=$1 expected_mode=$2
    [[ -f "$path" ]] || {
        echo "required file is missing" >&2
        exit 1
    }
    [[ $(stat -c '%a' "$path") == "$expected_mode" ]] || {
        echo "file permissions are invalid" >&2
        exit 1
    }
    [[ $(stat -c '%u' "$path") == 1000 ]] || {
        echo "file owner is invalid" >&2
        exit 1
    }
}

require_client_representation() {
    local compact
    compact=$(tr -d '[:space:]' <<<"$1")
    for expected in \
        '"clientId":"mcp-gateway"' \
        '"publicClient":false' \
        '"clientAuthenticatorType":"client-secret"' \
        '"standardFlowEnabled":true' \
        '"implicitFlowEnabled":false' \
        '"directAccessGrantsEnabled":false' \
        '"serviceAccountsEnabled":false' \
        '"redirectUris":["http://localhost:8080/auth/callback"]' \
        '"webOrigins":[]' \
        '"pkce.code.challenge.method":"S256"' \
        '"post.logout.redirect.uris":"http://localhost:8080/auth/logged-out"'; do
        [[ "$compact" == *"$expected"* ]] || {
            echo "reconciled client does not satisfy the Phase 00 contract" >&2
            exit 1
        }
    done
}

if [[ -f "$marker" && -s "$client_secret_file" ]]; then
    require_secure_file "$marker" 600
    require_secure_file "$client_secret_file" 400
    echo "client initializer found persistent marker, skipping Admin API"
    exit 0
fi

[[ "$public_base" == http://localhost:8080 && "$admin_server" == http://localhost:8080/idp ]] || {
    echo "MCP_GATEWAY_PUBLIC_BASE_URL must be the fixed demo public URL" >&2
    exit 1
}
[[ -s "$bootstrap_password_file" ]] || {
    echo "bootstrap password is required for first initialization" >&2
    exit 1
}
require_secure_file "$bootstrap_password_file" 400
require_secure_file "$client_secret_file" 400

wait_for_health() {
    local response
    for _ in {1..60}; do
        if exec 3<>/dev/tcp/127.0.0.1/9000 2>/dev/null; then
            printf 'GET /idp/health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
            response=$(cat <&3)
            if [[ "$response" == *'"status"'*'"UP"'* ]]; then
                return
            fi
        fi
        sleep 1
    done
    echo "Keycloak health endpoint did not become ready" >&2
    exit 1
}

wait_for_health

bootstrap_password=$(<"$bootstrap_password_file")
/opt/keycloak/bin/kcadm.sh config credentials \
    --server "$admin_server" \
    --realm master \
    --user bootstrap-admin \
    --password "$bootstrap_password" >/dev/null
unset bootstrap_password

client_json=$(mktemp)
client_update_response=$(mktemp)
cleanup_client_json=$(mktemp)
cleanup_config=$(mktemp)
trap 'rm -f "$client_json" "$client_update_response" "$cleanup_client_json" "$cleanup_config"' EXIT
client_secret=$(<"$client_secret_file")
cat >"$client_json" <<JSON
{
  "clientId": "${client_id}",
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "${client_secret}",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "authorizationServicesEnabled": false,
  "redirectUris": ["${callback_url}"],
  "webOrigins": [],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "${logout_url}"
  }
}
JSON
unset client_secret

client_record=$(/opt/keycloak/bin/kcadm.sh get clients -r "$realm" -q "clientId=${client_id}")
client_uuid=$(printf '%s\n' "$client_record" | sed -n 's/^[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
[[ -n "$client_uuid" ]] || {
    echo "expected client was not imported" >&2
    exit 1
}
echo "reconciling confidential OIDC client"
if ! /opt/keycloak/bin/kcadm.sh update "clients/${client_uuid}" -r "$realm" -f "$client_json" >"$client_update_response" 2>&1; then
    echo "unable to reconcile confidential OIDC client through the Admin API" >&2
    if [[ -s "$client_update_response" ]] && ! grep -Eiq 'secret|password|token' "$client_update_response"; then
        echo "Keycloak Admin API response:" >&2
        cat "$client_update_response" >&2
    fi
    exit 1
fi
if ! client_representation=$(/opt/keycloak/bin/kcadm.sh get "clients/${client_uuid}" -r "$realm"); then
    echo "unable to read reconciled client from the Admin API" >&2
    exit 1
fi
require_client_representation "$client_representation"
echo "validated exact confidential OIDC client through the Admin API"
echo "creating ephemeral cleanup administrator"
cleanup_client_id="mcp-bootstrap-cleanup-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
cleanup_secret=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
cat >"$cleanup_client_json" <<JSON
{
  "clientId": "${cleanup_client_id}",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "${cleanup_secret}",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false
}
JSON
/opt/keycloak/bin/kcadm.sh create clients -r master -f "$cleanup_client_json" >/dev/null
cleanup_record=$(/opt/keycloak/bin/kcadm.sh get clients -r master -q "clientId=${cleanup_client_id}")
cleanup_client_uuid=$(printf '%s\n' "$cleanup_record" | sed -n 's/^[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
[[ -n "$cleanup_client_uuid" ]] || {
    echo "ephemeral cleanup administrator was not created" >&2
    exit 1
}
/opt/keycloak/bin/kcadm.sh add-roles -r master \
    --uusername "service-account-${cleanup_client_id}" \
    --cclientid master-realm \
    --rolename manage-users \
    --rolename query-users \
    --rolename manage-clients >/dev/null
/opt/keycloak/bin/kcadm.sh config credentials \
    --config "$cleanup_config" \
    --server "$admin_server" \
    --realm master \
    --client "$cleanup_client_id" \
    --secret "$cleanup_secret" >/dev/null
unset cleanup_secret

bootstrap_record=$(/opt/keycloak/bin/kcadm.sh get users -r master -q username=bootstrap-admin)
bootstrap_uuid=$(printf '%s\n' "$bootstrap_record" | sed -n 's/^[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
[[ -n "$bootstrap_uuid" ]] || {
    echo "temporary bootstrap administrator was not found" >&2
    exit 1
}
/opt/keycloak/bin/kcadm.sh delete "users/${bootstrap_uuid}" -r master --config "$cleanup_config" >/dev/null

if ! bootstrap_record=$(/opt/keycloak/bin/kcadm.sh get users -r master -q exact=true -q username=bootstrap-admin --config "$cleanup_config"); then
    echo "unable to verify temporary bootstrap administrator removal through the cleanup Admin API session" >&2
    exit 1
fi
[[ $(tr -d '[:space:]' <<<"$bootstrap_record") == '[]' ]] || {
    echo "temporary bootstrap administrator still exists" >&2
    exit 1
}
/opt/keycloak/bin/kcadm.sh delete "clients/${cleanup_client_uuid}" -r master --config "$cleanup_config" >/dev/null
echo "$bootstrap_absent_message"
rm -f "$bootstrap_password_file"

marker_tmp=$(mktemp "${marker}.tmp.XXXXXX")
printf 'client initialized\n' >"$marker_tmp"
chown 1000:0 "$marker_tmp"
chmod 0600 "$marker_tmp"
mv "$marker_tmp" "$marker"
