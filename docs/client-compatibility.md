# Client compatibility

v0.1 uses personal access tokens (PATs), not client OAuth. Sign in through the
browser at `/auth` (or visit `/auth/token` to be redirected to sign-in), issue a
token once, then configure an MCP client to send
`Authorization: Bearer <token>` to the protected nginx URL, for example the
demo's `http://localhost:8080/echo/mcp`. The token page lists only servers
granted by the static YAML policy. The token is displayed only at issuance;
store it securely and revoke it when no longer needed.

This gateway does not expose MCP OAuth authorization-server discovery or dynamic
client registration. Clients that require that discovery, or cannot send a
custom bearer header, are not compatible with v0.1. nginx replaces the PAT
with the MCP service's own bearer credential; HTTP API routes strip the client
`Authorization` header and forward only the validated gateway user header.
Keycloak roles/groups and OpenFGA authorization are not implemented.
