"""Static contract checks for the nginx snippets and the reference server config.

These parse nginx block structure instead of matching whole-file substrings, so
they fail when a directive moves to the wrong location. Runtime behaviour
(statuses, header sanitization through a real nginx) is exercised by
`scripts/edge-contract-test.sh`, which needs Docker and is run separately.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
NGINX = ROOT / "deploy/nginx"
SNIPPETS = "/etc/nginx/snippets"
CONTROL_HEADERS = (
    "X-MCP-Gateway-Server",
    "X-MCP-Gateway-Original-URI",
    "X-MCP-Gateway-User",
    "X-MCP-Gateway-Upstream-Token",
)
SNIPPET_KIND = {"mcp-gateway-mcp.conf": "mcp", "mcp-gateway-http-api.conf": "http_api"}


def _source(name: str) -> str:
    return (NGINX / name).read_text(encoding="utf-8")


def _blocks(source: str) -> list[tuple[str, str]]:
    """Return (header, body) for each top-level block of an nginx source.

    Comments and quoted strings are skipped so JSON bodies and regexes cannot
    unbalance the scan. Nested blocks (`if`, `location` inside `server`) stay in
    the body; call again on a body to descend.
    """
    blocks: list[tuple[str, str]] = []
    depth = 0
    statement_start = 0
    body_start = 0
    header = ""
    quote = ""
    escaped = False
    comment = False
    for index, char in enumerate(source):
        if comment:
            comment = char != "\n"
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char == "#":
            comment = True
        elif char in "\"'":
            quote = char
        elif char == ";" and depth == 0:
            statement_start = index + 1
        elif char == "{":
            if depth == 0:
                raw_header = re.sub(r"(?m)#.*$", "", source[statement_start:index])
                header = " ".join(raw_header.split())
                body_start = index + 1
            depth += 1
        elif char == "}":
            depth -= 1
            assert depth >= 0, "unbalanced nginx braces"
            if depth == 0:
                blocks.append((header, source[body_start:index]))
                statement_start = index + 1
    assert depth == 0 and not quote, "unbalanced nginx braces or quotes"
    return blocks


def _locations(source: str) -> dict[str, str]:
    locations: dict[str, str] = {}
    for header, body in _blocks(source):
        if header.startswith("location "):
            assert header not in locations, f"duplicate {header}"
            locations[header] = body
    return locations


def _top_level(body: str) -> str:
    """Directives of a block body with nested blocks removed."""
    stripped = body
    for _header, inner in _blocks(body):
        stripped = stripped.replace(inner, "", 1)
    return re.sub(r"(?m)#.*$", "", stripped)


def _has(body: str, directive: str) -> bool:
    words = directive.split()
    pattern = r"\s+".join(re.escape(word) for word in words)
    return re.search(rf"(?m)^\s*{pattern}\s*;", _top_level(body)) is not None


def _only_returns_404(body: str) -> bool:
    return re.fullmatch(r"\s*return\s+404\s*;\s*", re.sub(r"(?m)#.*$", "", body)) is not None


def _protected_locations() -> dict[str, tuple[str, str, str]]:
    """Map protected prefix -> (selected server, snippet name, body) in default.conf."""
    (server,) = [body for header, body in _blocks(_source("default.conf")) if header == "server"
                 and "server_name" in _top_level(body)]
    protected: dict[str, tuple[str, str, str]] = {}
    for header, body in _locations(server).items():
        include = re.search(rf"include\s+{SNIPPETS}/(mcp-gateway-[a-z-]+\.conf)\s*;", body)
        if not include:
            continue
        match = re.fullmatch(r"location \^~ (/\S*)", header)
        assert match, f"protected {header} must be a ^~ prefix location"
        selected = re.search(r"set\s+\$mcp_gateway_server\s+([a-z0-9-]+)\s*;", body)
        assert selected, f"{header} does not select a registry server"
        protected[match.group(1)] = (selected.group(1), include.group(1), body)
    return protected


def test_only_auth_routes_proxy_to_the_public_gateway() -> None:
    routes = _locations(_source("mcp-gateway.locations.conf"))
    # The operator server owns `/`; a catch-all here would collide with it.
    assert "location /" not in routes
    proxying = {header for header, body in routes.items() if "proxy_pass" in body}
    assert proxying == {"location = /auth", "location ^~ /auth/", "location = /_authz"}
    for header in ("location = /auth", "location ^~ /auth/"):
        body = routes[header]
        assert _has(body, "proxy_pass http://$mcp_gateway_upstream")
        assert _has(body, 'proxy_set_header Authorization ""')
        for name in CONTROL_HEADERS:
            assert _has(body, f'proxy_set_header {name} ""'), (header, name)
            assert _has(body, f"proxy_hide_header {name}"), (header, name)
        methods = [inner for if_header, inner in _blocks(body) if "$request_method" in if_header]
        assert methods and all(_only_returns_404(inner) for inner in methods)


def test_authz_subrequest_is_internal_and_binds_server_to_original_uri() -> None:
    body = _locations(_source("mcp-gateway.locations.conf"))["location = /_authz"]
    assert _has(body, "internal")
    assert _has(body, "proxy_pass http://$mcp_gateway_upstream/introspect")
    assert _has(body, "proxy_method GET")
    assert _has(body, "proxy_pass_request_body off")
    assert _has(body, 'proxy_set_header Cookie ""')
    assert _has(body, "proxy_set_header X-MCP-Gateway-Server $mcp_gateway_server")
    assert _has(body, "proxy_set_header X-MCP-Gateway-Original-URI $mcp_gateway_original_uri")
    for name in ("X-MCP-Gateway-User", "X-MCP-Gateway-Upstream-Token"):
        assert _has(body, f'proxy_set_header {name} ""')


def test_every_public_introspection_spelling_is_denied_without_proxying() -> None:
    routes = _locations(_source("mcp-gateway.locations.conf"))
    assert _only_returns_404(routes["location ^~ /introspect"])
    assert _only_returns_404(routes["location ^~ /_authz/"])
    regexes = {header: body for header, body in routes.items() if header.startswith("location ~")}
    assert regexes and all(_only_returns_404(body) for body in regexes.values())
    compiled = []
    for header in regexes:
        raw = header.split(None, 2)[2]
        # A regex holding `;` or `{` must be quoted or nginx ends the directive early.
        if re.search(r"[;{}]", raw):
            assert raw[0] == raw[-1] and raw[0] in "\"'", f"unquoted regex in {header}"
        flags = re.IGNORECASE if header.startswith("location ~* ") else 0
        compiled.append(re.compile(raw.strip("\"'"), flags))
    # nginx decodes %XX and merges slashes before matching, so /%69ntrospect is
    # /introspect; the regex covers raw spellings when merge_slashes is off.
    for path in ("/introspect", "/introspect/", "//introspect", "/introspect;x",
                 "/INTROSPECT", "/_authz", "//_authz/x"):
        assert any(pattern.search(path) for pattern in compiled), path
    for path in ("/auth/token", "/echo/introspect", "/introspection-docs"):
        assert not any(pattern.search(path) for pattern in compiled), path


def test_json_error_locations_return_exact_statuses() -> None:
    routes = _locations(_source("mcp-gateway.locations.conf"))
    for name, status in (("unauthorized", 401), ("forbidden", 403), ("unavailable", 503)):
        body = routes[f"location @mcp_gateway_{name}"]
        assert _has(body, "default_type application/json")
        assert re.search(rf"(?m)^\s*return\s+{status}\s+'\{{\"error\":\"{name}\"", body)
    assert re.search(
        r"add_header\s+WWW-Authenticate\s+'Bearer realm=\"mcp-gateway\"'\s+always\s*;",
        routes["location @mcp_gateway_unauthorized"],
    )


def test_protected_snippets_sanitize_headers_and_split_credentials() -> None:
    mcp = _source("mcp-gateway-mcp.conf")
    api = _source("mcp-gateway-http-api.conf")
    for body in (mcp, api):
        assert _has(body, "auth_request /_authz")
        assert _has(body, "auth_request_set $mcp_gateway_user $upstream_http_x_mcp_gateway_user")
        assert _has(body, "error_page 401 = @mcp_gateway_unauthorized")
        assert _has(body, "error_page 403 = @mcp_gateway_forbidden")
        assert _has(body, "error_page 500 502 503 504 = @mcp_gateway_unavailable")
        for name in CONTROL_HEADERS:
            value = "$mcp_gateway_user" if name == "X-MCP-Gateway-User" else '""'
            assert _has(body, f"proxy_set_header {name} {value}"), name
            assert _has(body, f"proxy_hide_header {name}"), name
        # Exactly one Authorization decision per snippet; nothing later overrides it.
        assert len(re.findall(r"(?m)^\s*proxy_set_header\s+Authorization\b", body)) == 1
    assert _has(
        mcp,
        "auth_request_set $mcp_gateway_upstream_token $upstream_http_x_mcp_gateway_upstream_token",
    )
    assert _has(mcp, 'proxy_set_header Authorization "Bearer $mcp_gateway_upstream_token"')
    assert _has(api, 'proxy_set_header Authorization ""')
    assert "upstream_token" not in _top_level(api)


def test_reference_server_terminates_tls_and_defaults_to_404() -> None:
    blocks = [body for header, body in _blocks(_source("default.conf")) if header == "server"]
    for body in blocks:
        listens = re.findall(r"(?m)^\s*listen\s+([^;]+);", _top_level(body))
        assert listens and all(re.search(r"\bssl\b", listen) for listen in listens)
    (main,) = [body for body in blocks if _has(body, "server_name gateway.example.com")]
    assert _has(main, "ssl_certificate /etc/nginx/tls/tls.crt")
    assert _has(main, "ssl_certificate_key /etc/nginx/tls/tls.key")
    assert _has(main, f"include {SNIPPETS}/mcp-gateway.locations.conf")
    assert _only_returns_404(_locations(main)["location /"])
    (fallback,) = [body for body in blocks if body is not main]
    assert _has(fallback, "ssl_reject_handshake on")


def test_protected_locations_match_registry_entries_exactly() -> None:
    registry = yaml.safe_load((ROOT / "examples/registry.yaml").read_text(encoding="utf-8"))
    entries = {entry["path"]: entry for entry in registry["servers"]}
    protected = _protected_locations()
    assert set(protected) == set(entries)
    for prefix, (server, snippet, body) in protected.items():
        entry = entries[prefix]
        assert entry["name"] == server
        assert SNIPPET_KIND[snippet] == entry["kind"]
        # Both bindings must be set before the snippet's auth_request runs.
        order = re.search(
            r"(?s)set\s+\$mcp_gateway_server\s+\S+\s*;.*?"
            r"set\s+\$mcp_gateway_original_uri\s+\$request_uri\s*;.*?"
            rf"include\s+{SNIPPETS}/{re.escape(snippet)}\s*;.*?proxy_pass\s+http://\S+\s*;",
            body,
        )
        assert order, prefix
        # Locations must not re-introduce client credentials or gateway headers.
        assert not re.search(r"proxy_set_header\s+(Authorization|X-MCP-Gateway-)", body), prefix
