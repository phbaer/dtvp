FROM node:24-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=secret,id=build_ca,target=/run/secrets/build_ca \
    if [ -f /run/secrets/build_ca ]; then NODE_EXTRA_CA_CERTS=/run/secrets/build_ca npm ci --include=optional; else npm ci --include=optional; fi
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev
COPY dtvp ./dtvp
COPY alembic.ini ./
COPY playground/fixtures ./playground/fixtures
COPY --from=frontend /app/frontend/dist ./frontend/dist
RUN useradd --uid 10001 --create-home dtvp && mkdir /data && chown dtvp:dtvp /data
USER dtvp
ENV DTVP_ARTIFACT_DIR=/data/artifacts
ENV UV_CACHE_DIR=/tmp/uv PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["uv", "run", "--no-sync", "python", "-m", "dtvp.cli", "serve", "--host", "0.0.0.0"]
