# Override the complete reference only when intentionally updating the pinned base.
ARG PYTHON_IMAGE=python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92

# Stage 1: Build the frontend
FROM node:lts-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS frontend-build

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package*.json ./

# Install frontend dependencies, including native optional packages used by Vite/Rolldown.
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -s /tmp/ca-certs.crt ]; then \
        NODE_EXTRA_CA_CERTS=/tmp/ca-certs.crt npm ci --include=optional; \
    else \
        npm ci --include=optional; \
    fi

# Copy frontend source code
COPY frontend/ ./

# vue-tsc type-checks frontend test sources, which import the canonical rules.
COPY data/rescore_rules.json /app/data/rescore_rules.json

# Build the frontend for production
RUN npm run build

# Stage 2: Build the backend and include frontend assets
FROM ${PYTHON_IMAGE}

ARG BUILD_COMMIT=unknown
ENV DTVP_BUILD_COMMIT=$BUILD_COMMIT

WORKDIR /app

# Optionally add a private CA to the runtime trust store for internal OIDC and
# integration HTTPS endpoints. BuildKit keeps the source bundle out of context.
RUN --mount=type=secret,id=ca-certs,target=/tmp/ca-certs.crt \
    if [ -s /tmp/ca-certs.crt ]; then \
        cat /tmp/ca-certs.crt >> /etc/ssl/certs/ca-certificates.crt; \
    fi

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.9@sha256:6b6fa841d71a48fbc9e2c55651c5ad570e01104d7a7d701f57b2b22c0f58e9b1 /uv /bin/uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies using uv
# --frozen ensures we use the exact versions from uv.lock
# --no-dev excludes development dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY dtvp ./dtvp
COPY start.sh CHANGELOG.md ./
COPY sbom/dtvp-frontend-cyclonedx.json /app/sbom/dtvp-frontend-cyclonedx.json
COPY sbom/dtvp-backend-cyclonedx.json /app/sbom/dtvp-backend-cyclonedx.json
RUN chmod +x start.sh

# Copy the built frontend from the frontend-build stage
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Run the service without root privileges. Compose can override this UID/GID
# to match the owner of its bind-mounted data directory.
RUN addgroup -S -g 10001 dtvp \
    && adduser -S -D -H -u 10001 -G dtvp dtvp \
    && mkdir -p /app/data \
    && chown -R 10001:10001 /app/data
ENV HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001

# Expose the port
EXPOSE 8000

# Run the application using the startup script
CMD ["/app/start.sh"]
