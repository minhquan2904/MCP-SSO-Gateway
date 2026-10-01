#!/bin/sh
set -eu

write_secret() {
    destination=$1
    bytes=$2

    if [ -s "$destination" ]; then
        return
    fi

    umask 077
    tmp="${destination}.tmp"
    # URL-safe alphabet: OAuth client_secret_basic form-decodes credentials,
    # so '+', '/' and '=' would corrupt a raw secret.
    dd if=/dev/urandom bs="$bytes" count=1 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\n' >"$tmp"
    chown 1000:0 "$tmp"
    chmod 0400 "$tmp"
    mv "$tmp" "$destination"
}

prepare_volume() {
    directory=$1
    mkdir -p "$directory"
    chown 1000:0 "$directory"
    chmod 0700 "$directory"
}

prepare_volume /run/secrets/bootstrap-admin
prepare_volume /run/secrets/oidc-client
prepare_volume /run/secrets/gateway-session
prepare_volume /run/secrets/echo-token

if [ ! -f /run/secrets/bootstrap-admin/initialized ]; then
    write_secret /run/secrets/bootstrap-admin/password 36
    : > /run/secrets/bootstrap-admin/initialized
    chown 1000:0 /run/secrets/bootstrap-admin/initialized
    chmod 0400 /run/secrets/bootstrap-admin/initialized
fi
write_secret /run/secrets/oidc-client/client-secret 48
write_secret /run/secrets/gateway-session/session-secret 48
write_secret /run/secrets/echo-token/token 48
