# Override the complete reference only when intentionally updating the pinned base.
ARG PYTHON_IMAGE=python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92
FROM ${PYTHON_IMAGE}
WORKDIR /app
ENV UV_SYSTEM_CERTS=true

ARG BUILD_NUMBER=unknown
ARG AGENTYZER_BUILD_VERSION
ENV AGENTYZER_BUILD_VERSION=$AGENTYZER_BUILD_VERSION

COPY --from=ghcr.io/astral-sh/uv:0.11.31@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437 /uv /bin/uv

# Trust local / corporate CA certificates before installing runtime packages.
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -s /tmp/ca-certs.crt ]; then \
        cat /tmp/ca-certs.crt >> /etc/ssl/certs/ca-certificates.crt; \
    fi \
    && apk add --no-cache git libarchive-tools

COPY pyproject.toml uv.lock README.md ./
COPY src/__init__.py src/build_version.py ./src/
RUN test -n "$AGENTYZER_BUILD_VERSION" && uv sync --frozen --no-dev

COPY config/prompts ./config/prompts
COPY config/repos.container.yaml ./config/repos.yaml
COPY src ./src
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

RUN addgroup -S -g 10001 agentyzer \
    && adduser -S -D -H -u 10001 -G agentyzer -s /sbin/nologin agentyzer \
    && mkdir -p /app/repos \
    && chown -R 10001:10001 /app/repos
ENV PYTHONPATH=/app \
    AGENTYZER_CONFIG_DIR=/app/config \
    AGENTYZER_REPOS_DIR=/app/repos \
    AGENTYZER_BUILD_NUMBER=$BUILD_NUMBER \
    HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["/app/start.sh"]
