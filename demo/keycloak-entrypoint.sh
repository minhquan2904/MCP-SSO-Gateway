#!/bin/bash
set -euo pipefail

marker=/opt/keycloak/data/mcp-gateway-client-initialized
bootstrap_password_file=/run/secrets/bootstrap-admin/password

if [[ ! -f "$marker" ]]; then
    [[ -s "$bootstrap_password_file" ]] || {
        echo "bootstrap password is required before first initialization" >&2
        exit 1
    }

    echo "starting first Keycloak initialization"
    export KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin
    export KC_BOOTSTRAP_ADMIN_PASSWORD
    KC_BOOTSTRAP_ADMIN_PASSWORD=$(<"$bootstrap_password_file")
else
    echo "starting Keycloak with persistent initialization marker"
fi

exec /opt/keycloak/bin/kc.sh start --import-realm
