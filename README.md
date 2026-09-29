# MCP SSO Gateway

Single sign-on and per-server authorization for self-hosted
[MCP](https://modelcontextprotocol.io) servers, enforced at your nginx.

Many MCP servers are protected by one shared static token that everyone
copies into their client config. MCP SSO Gateway replaces that with:

- **SSO sign-in** through any OIDC provider (Keycloak is the reference).
- **Personal tokens**: one per device, 90-day expiry, revocable, stored only
  as a hash.
- **Per-server authorization**: a user can be allowed on one MCP server and
  denied on another. The policy backend is pluggable: static file, Keycloak
  roles and groups, or OpenFGA.
- **Token exchange at the edge**: nginx swaps the personal token for the
  upstream's own static token, so upstream servers need **no code change**
  and never see a user's token.
- **Ready-made client setup**: after sign-in the gateway prints the config
  for Claude Code (`claude mcp add` / `.mcp.json`) and Claude Desktop (via
  `mcp-remote`).

> **Status: early development.** The code is being extracted from an in-house
> deployment and generalized. This README describes the target design, and the
> diagrams below show how it works. Nothing is released yet, but
> [`demo/`](demo/) runs the core token exchange with `docker compose up`.

## How it works

The gateway is a small FastAPI service behind nginx. nginx calls it with
[`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
on every request to a protected path. The gateway answers 200, 401 or 403,
and on success returns the headers nginx forwards upstream.

### 1. Sign-in and token issuance

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/sign-in/sign-in-dark.svg">
  <img alt="Sequence: developer signs in through Keycloak and receives a personal token" src="docs/architecture/sign-in/sign-in-light.svg">
</picture>

- Standard OIDC authorization code flow with PKCE. The callback query
  (`code`, `state`) is never written to access logs.
- The token is shown once. Only its SHA-256 hash is stored. A token is issued
  only if the user may use at least one server, and the printed client config
  lists only the servers that user is allowed to use.
- The printed `.mcp.json` reads the token from an environment variable, so the
  file is safe to commit. The token itself goes into the shell profile.
- The session cookie has its own name and is scoped to `/auth`. Other apps and
  upstreams on the same host never receive it.

### 2. Calling an upstream through the gateway

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/request-flow/request-flow-dark.svg">
  <img alt="Sequence: nginx asks the gateway, then forwards to an MCP server with its static token, or to an HTTP API without credentials" src="docs/architecture/request-flow/request-flow-light.svg">
</picture>

- The token identifies a person. **nginx**, not the client, decides which
  server is being accessed, so a client cannot ask to be checked against a
  different server.
- **MCP servers that expect a static token**: nginx replaces `Authorization`
  with that server's token.
- **Internal HTTP APIs with no auth of their own**: nginx strips
  `Authorization` and forwards only the user header.
- Rejections return JSON with a `how_to_fix` hint instead of an nginx HTML
  page, because MCP clients show the response body to the user.

### 3. Token exchange in detail

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/token-exchange/token-exchange-dark.svg">
  <img alt="Sequence: token lookup, policy check, upstream secret read, header swap, and the rejection path" src="docs/architecture/token-exchange/token-exchange-light.svg">
</picture>

- **One source of truth for the upstream secret.** The upstream's own secret
  file is mounted read-only into both containers, so there is no copy to keep
  in sync. The upstream keeps checking its token, which means direct calls
  inside the network are still rejected.
- **Fail closed.** If the gateway or the policy backend is unreachable, the
  request is denied. Policy decisions are cached for 60 seconds, so removing a
  grant takes effect within a minute.
- **Revocation applies to new requests.** Streams that are already open are
  not cut when a token or grant is revoked.

Diagram sources live in [`docs/architecture/`](docs/architecture/).

## Design constraints

- nginx is the only ingress. The gateway and the upstream MCP servers must not
  publish ports.
- Only nginx may call the introspection endpoint, because its 200 response
  carries the upstream secret. The gateway compares the TCP peer with the
  address its container name resolves to, and rejects any other caller before
  it looks at the token. Other containers on the same network therefore cannot
  use a valid personal token to read an upstream secret.
- The peer check needs the real peer address, so the gateway must not trust
  `X-Forwarded-For` or similar proxy headers.
- Locations that skip `auth_request`, such as health checks, must clear the
  user header and the `Authorization` header themselves.
- This is **not** an OAuth 2.1 authorization server for MCP. Clients send a
  bearer token they were given. Clients that only support the MCP OAuth flow,
  such as connectors that cannot set a custom header, are out of scope for
  now.

## License

[Apache License 2.0](LICENSE)
