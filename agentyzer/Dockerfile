FROM ghcr.io/astral-sh/uv:0.11.9-python3.14-trixie-slim@sha256:45f13a5874be3c7d8264094f8884cc0b73e877fb973d5f64252ca4a952dbbbb9
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Trust local / corporate CA certificates injected at build time
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -s /tmp/ca-certs.crt ]; then \
        cat /tmp/ca-certs.crt >> /etc/ssl/certs/ca-certificates.crt; \
    fi

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

COPY config/prompts ./config/prompts
COPY config/repos.container.yaml ./config/repos.yaml
COPY src ./src

RUN groupadd --gid 10001 agentyzer \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app \
        --shell /usr/sbin/nologin agentyzer \
    && mkdir -p /app/repos \
    && chown -R 10001:10001 /app/repos
ENV PYTHONPATH=/app \
    AGENTYZER_CONFIG_DIR=/app/config \
    AGENTYZER_REPOS_DIR=/app/repos \
    HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
