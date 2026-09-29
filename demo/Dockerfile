FROM python:3.12-slim

RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "pyyaml>=6.0" \
 && useradd --system --uid 10001 gateway \
 && install -d -o gateway /data

WORKDIR /app
COPY gateway.py .
USER gateway

# --no-proxy-headers: the caller check must see the real peer address, not
# whatever X-Forwarded-For says.
CMD ["uvicorn", "gateway:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--no-proxy-headers", "--no-server-header"]
