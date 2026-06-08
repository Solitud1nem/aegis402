# Aegis402 core — offline-capable guard service.
# Builds without ML extras so the image needs no model download or external keys.
FROM python:3.12-slim

# uv for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8402 \
    AEGIS_DB_PATH=/data/aegis402.db

WORKDIR /app

# Install dependencies first (cached layer) using only the lockfile + manifest.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# Evidence DB lives on a volume so it survives restarts.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8402

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8402/health').status==200 else 1)"

CMD ["aegis402", "serve"]
