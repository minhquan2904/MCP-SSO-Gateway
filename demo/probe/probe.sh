#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Phase 00 probe for the dedicated Keycloak-only topology. It never touches demo/compose.yaml.
readonly compose_file=demo/keycloak-probe.compose.yaml
readonly compose_profile=keycloak-probe
readonly project=mcp-sso-gateway-probe
readonly network=mcp-sso-gateway-probe-idp
readonly curl_image=curlimages/curl:8.12.1
readonly public_base=http://localhost:8080
readonly issuer=http://localhost:8080/idp/realms/mcp-demo
readonly callback_encoded=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback
readonly challenge=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~
readonly marker_message="client initializer found persistent marker, skipping Admin API"
readonly bootstrap_absent_message="verified temporary bootstrap administrator is absent"

workdir=$(mktemp -d)
compose() {
    docker compose -p "$project" -f "$compose_file" --profile "$compose_profile" "$@"
}
cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() {
    echo "$*" >&2
    exit 1
}

require_status() {
    local expected=$1 url=$2 status
    status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$url")
    [[ "$status" == "$expected" ]] || fail "expected ${expected} from ${url}, received ${status}"
}

require_not_404() {
    local url=$1 status
    status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$url")
    [[ "$status" != 404 ]] || fail "allowlisted path returned 404: ${url}"
}

assert_tracked_files_have_no_secrets() {
    if grep -Eiq '"(secret|clientSecret)"|client-secret|bootstrap.*password' demo/keycloak/realm.json; then
        fail "tracked realm contains secret material"
    fi
    if grep -Eiq '(secret|password|token)=' demo/.env.example; then
        fail "demo/.env.example contains secret-looking values"
    fi
}

assert_public_allowlist() {
    local base="$public_base/idp/realms/mcp-demo/protocol/openid-connect"
    local discovery="$public_base/idp/realms/mcp-demo/.well-known/openid-configuration"
    local body="$workdir/auth.html"
    local authorization="$base/auth?client_id=mcp-gateway&redirect_uri=${callback_encoded}&response_type=code&scope=openid&code_challenge=${challenge}&code_challenge_method=S256"
    local discovered_issuer login_action login_action_url resource resource_url

    require_status 200 "$discovery"
    discovered_issuer=$(curl --silent --show-error \
        --header 'Host: untrusted.example' \
        --header 'X-Forwarded-For: 203.0.113.7' \
        --header 'X-Forwarded-Host: untrusted.example' \
        --header 'X-Forwarded-Proto: https' \
        "$discovery" | tr -d '\n' | sed -n 's/.*"issuer"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [[ "$discovered_issuer" == "$issuer" ]] || fail "public discovery did not report the fixed public issuer"
    require_status 200 "$base/certs"
    curl --silent --show-error --output "$body" "$authorization"
    login_action=$(tr '\n' ' ' <"$body" | sed -n 's/.*action="\([^" ]*\/login-actions\/[^" ]*\)".*/\1/p')
    resource=$(tr '\n' ' ' <"$body" | sed -n 's/.*href="\([^" ]*\/resources\/[^" ]*\)".*/\1/p')
    [[ -n "$login_action" ]] || fail "authorization response did not contain a login-actions URL"
    [[ -n "$resource" ]] || fail "authorization response did not contain a resources URL"
    login_action=${login_action//&amp;/&}
    resource=${resource//&amp;/&}
    case "$login_action" in
        http://*|https://*) login_action_url=$login_action ;;
        *) login_action_url="$public_base$login_action" ;;
    esac
    case "$resource" in
        http://*|https://*) resource_url=$resource ;;
        *) resource_url="$public_base$resource" ;;
    esac
    require_not_404 "$login_action_url"
    require_not_404 "$resource_url"
    require_not_404 "$base/logout"

    for blocked in \
        /admin/ \
        /idp/admin/ \
        /idp/admin/realms/mcp-demo/clients \
        /idp/realms/master/ \
        /idp/realms/master/protocol/openid-connect/auth \
        /idp/realms/mcp-demo/admin/ \
        /idp/metrics \
        /idp/health \
        /idp/health/ready \
        /idp/realms/mcp-demo/protocol/openid-connect/token \
        /idp/not-allowlisted; do
        require_status 404 "$public_base$blocked"
    done
}

assert_public_client_restrictions() {
    local base="$public_base/idp/realms/mcp-demo/protocol/openid-connect"
    local result status location

    # Implicit flow must be rejected: no login form and no token in the redirect.
    result=$(curl --silent --output "$workdir/implicit.html" --write-out '%{http_code} %{redirect_url}' \
        "$base/auth?client_id=mcp-gateway&redirect_uri=${callback_encoded}&response_type=token&scope=openid&code_challenge=${challenge}&code_challenge_method=S256")
    status=${result%% *}
    location=${result#* }
    [[ "$status" != 200 ]] || fail "implicit flow request was accepted"
    [[ "$location" != *access_token=* ]] || fail "implicit flow issued a token"

    # PKCE is required.
    result=$(curl --silent --output /dev/null --write-out '%{http_code} %{redirect_url}' \
        "$base/auth?client_id=mcp-gateway&redirect_uri=${callback_encoded}&response_type=code&scope=openid")
    status=${result%% *}
    location=${result#* }
    [[ "$status" != 200 && "$location" != *code=* ]] || fail "authorization request without PKCE was accepted"

    # PKCE plain is not S256.
    result=$(curl --silent --output /dev/null --write-out '%{http_code} %{redirect_url}' \
        "$base/auth?client_id=mcp-gateway&redirect_uri=${callback_encoded}&response_type=code&scope=openid&code_challenge=${challenge}&code_challenge_method=plain")
    status=${result%% *}
    location=${result#* }
    [[ "$status" != 200 && "$location" != *code=* ]] || fail "PKCE plain was accepted"

    # Redirect URI matching is exact: no prefix or wildcard behavior.
    for redirect in \
        "${callback_encoded}%2Fextra" \
        http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallbackx \
        http%3A%2F%2Flocalhost%3A8080%2F ; do
        status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
            "$base/auth?client_id=mcp-gateway&redirect_uri=${redirect}&response_type=code&scope=openid&code_challenge=${challenge}&code_challenge_method=S256")
        [[ "$status" == 400 ]] || fail "non-exact redirect URI was not rejected (${status})"
    done

    # Post-logout redirect matching is exact.
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
        "$base/logout?client_id=mcp-gateway&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fevil")
    [[ "$status" == 400 ]] || fail "non-exact post-logout redirect URI was not rejected (${status})"
}

assert_client_usable_from_network() {
    docker run --rm --network "$network" \
        --user 1000:0 \
        -v "${project}_oidc-client:/run/secrets/oidc-client:ro" \
        --entrypoint /bin/sh "$curl_image" -ec '
            base=http://keycloak:8080/idp/realms/mcp-demo
            oidc=$base/protocol/openid-connect
            secret=$(cat /run/secrets/oidc-client/client-secret)

            discovery=$(curl --fail --silent "$base/.well-known/openid-configuration" | tr -d "\n")
            issuer=$(printf "%s" "$discovery" | sed -n "s/.*\"issuer\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
            [ "$issuer" = "http://localhost:8080/idp/realms/mcp-demo" ]
            token_endpoint=$(printf "%s" "$discovery" | sed -n "s/.*\"token_endpoint\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
            [ "$token_endpoint" = "$oidc/token" ]
            jwks_uri=$(printf "%s" "$discovery" | sed -n "s/.*\"jwks_uri\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
            [ "$jwks_uri" = "$oidc/certs" ]

            curl --fail --silent "$oidc/certs" | grep -q "\"keys\""

            code() { curl --silent --output /dev/null --write-out "%{http_code}" "$@"; }
            # Authorization-code exchange reaches confidential client authentication and code validation.
            [ "$(code --user "mcp-gateway:${secret}" --data grant_type=authorization_code --data code=not-a-code --data redirect_uri=http://localhost:8080/auth/callback --data code_verifier=x "$oidc/token")" = 400 ]
            # Wrong client secret is refused.
            [ "$(code --user "mcp-gateway:wrong-secret" --data grant_type=authorization_code --data code=not-a-code "$oidc/token")" = 401 ]
            # Direct access grants and service accounts are disabled.
            [ "$(code --user "mcp-gateway:${secret}" --data grant_type=password --data username=alice --data password=alice-demo-password "$oidc/token")" = 400 ]
            [ "$(code --user "mcp-gateway:${secret}" --data grant_type=client_credentials "$oidc/token")" = 401 ]
            # Back-channel logout exists. The same gateway-network client sees the nginx Admin deny.
            [ "$(code "$oidc/logout")" != 404 ]
            [ "$(code http://nginx:8080/idp/admin/realms/mcp-demo/clients)" = 404 ]
            [ "$(code http://keycloak:8080/idp/admin/realms/mcp-demo/clients)" != 200 ]
        '
}

assert_secret_isolation() {
    local service id mounts
    id=$(compose ps -q keycloak)
    mounts=$(docker inspect -f '{{range .Mounts}}{{println .Name}}{{end}}' "$id")
    [[ "$mounts" == *"${project}_keycloak-data"* ]] || fail "Keycloak lost persistent state volume"
    [[ "$mounts" == *"${project}_bootstrap-admin"* ]] || fail "Keycloak lost bootstrap volume mount"
    for unwanted in oidc-client gateway-session echo-token status-token; do
        [[ "$mounts" != *"${project}_${unwanted}"* ]] || fail "Keycloak mounts ${unwanted}"
    done

    # The initializer sees bootstrap and OIDC client files only.
    id=$(compose ps -a -q init-keycloak-client)
    mounts=$(docker inspect -f '{{range .Mounts}}{{println .Name}}{{end}}' "$id")
    [[ "$mounts" == *"${project}_bootstrap-admin"* && "$mounts" == *"${project}_oidc-client"* ]] || fail "client initializer lost required mounts"
    for unwanted in gateway-session echo-token status-token; do
        [[ "$mounts" != *"${project}_${unwanted}"* ]] || fail "client initializer mounts ${unwanted}"
    done

    # nginx has no secret volume at all.
    service=nginx
    id=$(compose ps -q "$service")
    mounts=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$id")
    [[ -z "$mounts" ]] || fail "nginx unexpectedly mounts a named volume"

    docker run --rm \
        -v "${project}_bootstrap-admin:/run/secrets/bootstrap-admin:ro" \
        --entrypoint /bin/sh busybox:1.37.0 -ec '
            test ! -e /run/secrets/bootstrap-admin/password
            test -f /run/secrets/bootstrap-admin/initialized
        '
}

assert_no_keycloak_host_port() {
    local id ports
    id=$(compose ps -q keycloak)
    ports=$(docker port "$id" || true)
    [[ -z "$ports" ]] || fail "Keycloak unexpectedly published a host port"
}

assert_no_probe_resources() {
    local kind
    for kind in "ps -aq" "network ls -q" "volume ls -q"; do
        # shellcheck disable=SC2086
        [[ -z "$(docker $kind --filter "label=com.docker.compose.project=${project}")" ]] \
            || fail "probe resources remain after down -v (${kind})"
    done
}

assert_all() {
    assert_no_keycloak_host_port
    echo "checking public allowlist and client restrictions"
    assert_public_allowlist
    assert_public_client_restrictions
    echo "checking private endpoints and client authentication"
    assert_client_usable_from_network
    echo "checking secret isolation"
    assert_secret_isolation
}

echo "starting fresh Keycloak-only OIDC probe topology"
assert_tracked_files_have_no_secrets
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --wait
fresh_log=$(compose logs init-keycloak-client)
[[ "$fresh_log" == *"$bootstrap_absent_message"* ]] || fail "initializer did not prove bootstrap administrator absence"
assert_all
echo "fresh probe topology assertions passed"

echo "recreating services with retained volumes"
compose down --remove-orphans
compose up -d --wait
marker_log=$(compose logs init-keycloak-client)
[[ "$marker_log" == *"$marker_message"* ]] || fail "initializer did not use the persistent marker path"
assert_all
echo "retained-volume restart assertions passed"

compose down -v --remove-orphans
assert_no_probe_resources
echo "probe completed and removed all probe resources"
trap - EXIT
rm -rf "$workdir"
