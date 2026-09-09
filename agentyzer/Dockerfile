FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim
WORKDIR /app

ARG BUILD_NUMBER=unknown
ARG AGENTYZER_BUILD_VERSION
ENV AGENTYZER_BUILD_VERSION=$AGENTYZER_BUILD_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends git unrar-free && rm -rf /var/lib/apt/lists/*

# Trust local / corporate CA certificates injected at build time
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -f /tmp/ca-certs.crt ]; then \
        cp /tmp/ca-certs.crt /usr/local/share/ca-certificates/extra.crt && \
        update-ca-certificates; \
    fi

COPY pyproject.toml uv.lock README.md ./
COPY src/__init__.py src/build_version.py ./src/
RUN test -n "$AGENTYZER_BUILD_VERSION" && uv sync --frozen --no-dev

COPY config ./config
COPY src ./src
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

ENV PYTHONPATH=/app
ENV AGENTYZER_CONFIG_DIR=/app/config
ENV AGENTYZER_REPOS_DIR=/app/repos
ENV AGENTYZER_BUILD_NUMBER=$BUILD_NUMBER
EXPOSE 8000
CMD ["/app/start.sh"]
