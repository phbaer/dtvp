FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Trust local / corporate CA certificates injected at build time
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -f /tmp/ca-certs.crt ]; then \
        cp /tmp/ca-certs.crt /usr/local/share/ca-certificates/extra.crt && \
        update-ca-certificates; \
    fi

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

COPY config ./config
COPY src ./src

ENV PYTHONPATH=/app
ENV AGENTYZER_CONFIG_DIR=/app/config
ENV AGENTYZER_REPOS_DIR=/app/repos
EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
