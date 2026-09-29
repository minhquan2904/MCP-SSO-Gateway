"""A stand-in for an MCP server that is protected by one shared static token.

Standard library only. It knows nothing about the gateway: it checks its own
token, exactly like an existing server would, and reports what it received so
the demo can show the token exchange.

    POST /mcp      requires `Authorization: Bearer <static token>`
    GET  /healthz  no auth; reports whether an Authorization header arrived
"""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN_FILE = Path(os.environ.get("ECHO_TOKEN_FILE", "/run/secrets/echo_token"))
PORT = int(os.environ.get("ECHO_PORT", "8000"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            # nginx must strip Authorization on locations that skip auth_request.
            self._send(200, {"ok": True,
                             "received_authorization": "Authorization" in self.headers})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send(404, {"error": "not_found"})
            return
        expected = "Bearer " + TOKEN_FILE.read_text().strip()
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            self._send(401, {"error": "invalid static token"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        self._send(200, {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "serverInfo": {"name": "echo", "version": "0.0.0"},
                # Set by nginx from the gateway's answer. The static token is shared,
                # so this header is the only way the upstream knows who is calling.
                "caller": self.headers.get("X-MCP-Gateway-User"),
            },
        })


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
