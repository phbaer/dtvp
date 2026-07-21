#!/bin/sh
set -eu

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$repository_dir/scripts/check-node-tls.sh"
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

mkdir -p "$repository_dir/sbom"

cd "$repository_dir"
UV_PROJECT_ENVIRONMENT="$temporary_dir/backend" uv sync --frozen --no-dev
uv run --frozen cyclonedx-py environment \
    "$temporary_dir/backend/bin/python" \
    --short-PURLs \
    --output-reproducible \
    -o sbom/dtvp-backend-cyclonedx.json \
    --sv 1.6 \
    --mc-type application \
    --pyproject pyproject.toml

cd "$repository_dir/frontend/sbom-tool"
npm ci --ignore-scripts
npm run generate -- \
    --omit dev \
    --mc-type application \
    --output-reproducible \
    -o ../../sbom/dtvp-frontend-cyclonedx.json \
    --package-lock-only ../package.json

cd "$repository_dir/agentyzer"
UV_PROJECT_ENVIRONMENT="$temporary_dir/agentyzer" uv sync --frozen --no-dev
"$repository_dir/.venv/bin/cyclonedx-py" environment \
    "$temporary_dir/agentyzer/bin/python" \
    --short-PURLs \
    --output-reproducible \
    -o ../sbom/agentyzer-cyclonedx.json \
    --sv 1.6 \
    --mc-type application \
    --pyproject pyproject.toml
