"""Server-rendered HTML for the token management UI.

All dynamic values are HTML-escaped at this layer. Styling is a small inline
stylesheet using system fonts only; no third-party assets are loaded.
"""

from __future__ import annotations

import html
import json

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1rem;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5; color: CanvasText; background: Canvas;
}
main { max-width: 40rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
.lead { margin: 0 0 1.5rem; opacity: 0.8; }
nav.tabs {
  display: flex; gap: 1rem; margin-bottom: 1.5rem;
  border-bottom: 1px solid color-mix(in srgb, CanvasText 20%, transparent);
}
nav.tabs a { text-decoration: none; padding: 0.4rem 0; color: inherit; }
nav.tabs a[aria-current="page"] { font-weight: 700; border-bottom: 2px solid currentColor; }
.card {
  border: 1px solid color-mix(in srgb, CanvasText 25%, transparent);
  border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.25rem;
}
.card h2 { font-size: 1.1rem; margin: 0 0 0.75rem; }
label { display: block; font-weight: 600; margin: 0.75rem 0 0.25rem; }
input[type="text"], input[type="password"] {
  width: 100%; padding: 0.5rem; border: 1px solid color-mix(in srgb, CanvasText 40%, transparent);
  border-radius: 4px; font: inherit; background: Field; color: FieldText;
}
button {
  margin-top: 1rem; padding: 0.5rem 1rem; font: inherit; cursor: pointer;
  border: 1px solid color-mix(in srgb, CanvasText 40%, transparent); border-radius: 4px;
  background: ButtonFace; color: ButtonText;
}
button.danger { color: #b30000; }
.alert { border-left: 4px solid currentColor; padding: 0.5rem 0.75rem; margin: 0.75rem 0; }
pre, code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.875rem;
}
pre.code {
  background: color-mix(in srgb, CanvasText 8%, transparent);
  padding: 0.75rem; border-radius: 4px; overflow-x: auto;
  white-space: pre-wrap; word-break: break-all;
}
table { border-collapse: collapse; width: 100%; }
th, td {
  text-align: left; padding: 0.4rem 0.5rem;
  border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent);
}
.muted { opacity: 0.7; }
.actions { display: flex; gap: 1.5rem; flex-wrap: wrap; }
"""

JS = """
function copyText(btn, text) {
  var done = function () {
    var old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = old; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () {});
  }
}
function confirmRevoke(form) {
  return confirm("Revoke the token labeled " + form.dataset.label + "?");
}
"""


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def layout(title: str, main: str, *, user: str | None = None, tab: str | None = None) -> str:
    who = f'<p class="muted">Signed in as {escape(user)}</p>' if user else ""
    tabs = ""
    if user:
        links = []
        for key, href, label in (
            ("token", "/auth/token", "Tokens"),
            ("mcp", "/auth/mcp", "Servers"),
        ):
            current = ' aria-current="page"' if key == tab else ""
            links.append(f'<a href="{href}"{current}>{label}</a>')
        tabs = f'<nav class="tabs">{"".join(links)}</nav>'
    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)} - MCP SSO Gateway</title>"
        f"<style>{CSS}</style></head><body><main>"
        + tabs
        + who
        + main
        + f"<script>{JS}</script></main></body></html>"
    )


def hero(title: str, lead: str) -> str:
    return f"<h1>{escape(title)}</h1><p class=\"lead\">{escape(lead)}</p>"


def alert(message_html: str) -> str:
    return f'<div class="alert" role="alert">{message_html}</div>'


def issue_card(csrf: str, label: str, *, replace: bool = False, error_html: str = "") -> str:
    replace_box = (
        '<label><input type="checkbox" name="replace" value="1" checked> '
        "Replace the existing token with this label</label>"
        if replace
        else ""
    )
    invalid = ' aria-invalid="true" aria-describedby="label-error"' if error_html else ""
    error = f'<p id="label-error" role="alert">{error_html}</p>' if error_html else ""
    return (
        '<section class="card"><h2>Issue a personal token</h2>'
        f"{error}"
        '<form method="post" action="/auth/token">'
        f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
        f'<label for="label">Machine label</label>'
        f'<input type="text" id="label" name="label" value="{escape(label)}" '
        'required maxlength="64" autocomplete="off"'
        f"{invalid}>"
        f"{replace_box}"
        '<button type="submit">Issue token</button>'
        "</form></section>"
    )


def no_access_card(*, retry_url: str) -> str:
    return (
        '<section class="card"><h2>No server access</h2>'
        "<p>Your account is not granted access to any server registered with this "
        "gateway. Ask an administrator to add your identity to the policy.</p>"
        f'<p><a href="{escape(retry_url)}">Reload</a></p></section>'
    )


def tokens_card(rows: list, csrf: str, fmt_time) -> str:
    if not rows:
        body = '<p class="muted">No active tokens.</p>'
    else:
        items = "".join(
            f"<tr><td>{escape(row.label)}</td><td>{fmt_time(row.created_at)}</td>"
            f"<td>{fmt_time(row.last_used_at) if row.last_used_at else 'never'}</td>"
            f"<td>{fmt_time(row.expires_at)}</td>"
            f'<td><form method="post" action="/auth/revoke" data-label="{escape(row.label)}" '
            f'onsubmit="return confirmRevoke(this)">'
            f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
            f'<input type="hidden" name="label" value="{escape(row.label)}">'
            '<button type="submit" class="danger">Revoke</button></form></td></tr>'
            for row in rows
        )
        body = (
            "<table><thead><tr><th>Label</th><th>Created</th><th>Last used</th>"
            f"<th>Expires</th><th></th></tr></thead><tbody>{items}</tbody></table>"
        )
    return f'<section class="card"><h2>Active tokens</h2>{body}</section>'


def code_window(content: str) -> str:
    return f'<pre class="code">{escape(content)}</pre>'


TOKEN_ENV = "MCP_GATEWAY_TOKEN"


def _server_config_block(servers: dict[str, str]) -> str:
    payload = {
        "mcpServers": {
            name: {
                "type": "http",
                "url": url,
                "headers": {"Authorization": f"Bearer ${{{TOKEN_ENV}}}"},
            }
            for name, url in servers.items()
        }
    }
    return json.dumps(payload, indent=2)


def issued_view(label: str, expires: str, token: str, servers: dict[str, str]) -> str:
    server_block = _server_config_block(servers)
    export_line = f"export {TOKEN_ENV}=<paste-your-token>"
    return (
        '<section class="card"><h2>Token issued</h2>'
        f"<p>Token for <strong>{escape(label)}</strong>, expires {escape(expires)}. "
        "It is shown only once; store it now.</p>"
        f"{code_window(token)}"
        f"<p>Export it before use:</p>{code_window(export_line)}"
        "</section>"
        '<section class="card"><h2>Client configuration</h2>'
        "<p>The configuration references the environment variable "
        f"<code>{TOKEN_ENV}</code> and never contains the token itself.</p>"
        f"{code_window(server_block)}"
        "</section>"
    )


def catalog_view(items: list[dict]) -> str:
    if not items:
        return (
            '<section class="card"><p class="muted">'
            'No servers are listed for your account.</p></section>'
        )
    rows = "".join(
        f"<tr><td>{escape(item['title'])}</td><td>{escape(item['description'])}</td>"
        f"<td>{'allowed' if item['allowed'] else 'denied'}</td>"
        f'<td><code>{escape(item["url"])}</code></td></tr>'
        for item in items
    )
    return (
        '<section class="card"><h2>Registered servers</h2>'
        "<table><thead><tr><th>Server</th><th>Description</th><th>Your access</th>"
        f"<th>URL</th></tr></thead><tbody>{rows}</tbody></table></section>"
    )


def error_view(title: str, message: str, *, action_href: str, action_label: str) -> str:
    return (
        f'<section class="card"><h2>{escape(title)}</h2><p>{escape(message)}</p>'
        f'<p><a href="{escape(action_href)}">{escape(action_label)}</a></p></section>'
    )


def logged_out_view() -> str:
    return (
        '<section class="card"><h2>Signed out</h2>'
        "<p>Your gateway session has ended. Personal tokens you issued remain "
        "valid until they expire or are revoked.</p>"
        '<p><a href="/auth">Sign in again</a></p></section>'
    )
