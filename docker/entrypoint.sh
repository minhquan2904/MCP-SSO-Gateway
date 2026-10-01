#!/bin/sh
set -eu
exec /app/.venv/bin/python -m uvicorn --host 0.0.0.0 --port 8000 --workers 1 --factory mcp_gateway.main:create_app --no-proxy-headers --no-server-header
