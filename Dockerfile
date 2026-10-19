FROM node:24-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=secret,id=build_ca,target=/run/secrets/build_ca \
    if [ -f /run/secrets/build_ca ]; then NODE_EXTRA_CA_CERTS=/run/secrets/build_ca npm ci --include=optional; else npm ci --include=optional; fi
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.13.1 AS uv
FROM python:3.15-slim-trixie
COPY --from=uv /uv /uvx /usr/local/bin/
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=secret,id=build_ca,target=/run/secrets/build_ca \
    if [ -f /run/secrets/build_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/build_ca > /tmp/dtvp-build-ca.pem && \
      SSL_CERT_FILE=/tmp/dtvp-build-ca.pem uv sync --locked --no-dev --no-install-project && rm /tmp/dtvp-build-ca.pem; \
    else uv sync --locked --no-dev --no-install-project; fi
COPY dtvp ./dtvp
RUN uv sync --locked --no-dev --offline
COPY alembic.ini ./
COPY playground/fixtures ./playground/fixtures
COPY --from=frontend /app/frontend/dist ./frontend/dist
RUN useradd --uid 10001 --create-home dtvp && mkdir /data && chown dtvp:dtvp /data
USER dtvp
ENV DTVP_ARTIFACT_DIR=/data/artifacts
ENV UV_CACHE_DIR=/tmp/uv PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["uv", "run", "--no-sync", "python", "-m", "dtvp.cli", "serve", "--host", "0.0.0.0"]
