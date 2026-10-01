"""Small observable MCP or HTTP API demo upstream."""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN_FILE = Path(os.environ.get("ECHO_TOKEN_FILE", "/run/secrets/echo-token/token"))
PORT = int(os.environ.get("ECHO_PORT", "8000"))
STATUS_MODE = os.environ.get("STATUS_MODE") == "true"


class Handler(BaseHTTPRequestHandler):
    def _headers(self) -> dict[str, str | None]:
        return {
            "authorization": self.headers.get("Authorization"),
            "x_mcp_gateway_user": self.headers.get("X-MCP-Gateway-User"),
            "x_mcp_gateway_upstream_token": self.headers.get("X-MCP-Gateway-Upstream-Token"),
            "x_mcp_gateway_server": self.headers.get("X-MCP-Gateway-Server"),
            "x_mcp_gateway_original_uri": self.headers.get("X-MCP-Gateway-Original-URI"),
        }

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"ok": True, **self._headers()})
        elif STATUS_MODE:
            self._send(200, {"ok": True, **self._headers()})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if STATUS_MODE:
            self._send(200, {"ok": True, **self._headers()})
            return
        if self.path != "/mcp":
            self._send(404, {"error": "not_found"})
            return
        expected = "Bearer " + TOKEN_FILE.read_text().strip()
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            self._send(401, {"error": "invalid static token", **self._headers()})
            return
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        self._send(
            200,
            {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"serverInfo": {"name": "echo", "version": "0.1"}, **self._headers()},
            },
        )


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
