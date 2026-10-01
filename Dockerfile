# Alpine base: the Debian slim images carry unfixed Critical/High OS findings
# that block the Trivy release gate. Pinned by digest; bump deliberately.
FROM python:3.12.14-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111 AS build
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY mcp_gateway ./mcp_gateway
RUN pip install --no-cache-dir --disable-pip-version-check uv==0.6.14 && uv sync --frozen --no-dev --no-editable

FROM python:3.12.14-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111
RUN addgroup -g 1000 gateway && adduser -u 1000 -G gateway -H -D -s /sbin/nologin gateway
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY docker/entrypoint.sh docker/healthcheck.py /app/docker/
RUN mkdir /data && chown gateway:gateway /data && chmod 0555 /app/docker/entrypoint.sh
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
# Internal port only; publish nginx, never the gateway.
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 CMD ["/app/.venv/bin/python", "/app/docker/healthcheck.py"]
ENTRYPOINT ["/app/docker/entrypoint.sh"]
