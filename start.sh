#!/bin/sh
set -e

# Print the packaged project version before importing the application so it is
# present in the container logs even when application initialization fails.
DTVP_VERSION=$(
    /app/.venv/bin/python -c 'import tomllib; print(tomllib.load(open("/app/pyproject.toml", "rb"))["project"]["version"])' 2>/dev/null ||
    true
)
DTVP_VERSION=${DTVP_VERSION:-unknown}
DTVP_BUILD_NUMBER=${DTVP_BUILD_NUMBER:-unknown}
printf 'DTVP version: %s (build number: %s)\n' "${DTVP_VERSION}" "${DTVP_BUILD_NUMBER}"

# Default DTVP_CONTEXT_PATH to / if not set
DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH:-/}

# Ensure DTVP_CONTEXT_PATH starts with / and remove trailing slash if present (unless it is just /)
if [ "$DTVP_CONTEXT_PATH" != "/" ]; then
    DTVP_CONTEXT_PATH="/$(echo "$DTVP_CONTEXT_PATH" | sed 's|^/||' | sed 's|/$||')"
fi

# Default DTVP_FRONTEND_URL to http://localhost:8000 if not set
DTVP_FRONTEND_URL=${DTVP_FRONTEND_URL:-http://localhost:8000}

# Default DTVP_DEFAULT_PROJECT_FILTER to empty if not set (used by Dashboard)
DTVP_DEFAULT_PROJECT_FILTER=${DTVP_DEFAULT_PROJECT_FILTER:-}

# Default attribution-age filter presets if not set (used by Project filters)
DTVP_ATTRIBUTION_AGE_FILTER_DAYS=${DTVP_ATTRIBUTION_AGE_FILTER_DAYS:-7d,14d,28d}

# Default dev-disable-auth flag if not set (used by frontend bootstrap)
DTVP_DEV_DISABLE_AUTH=${DTVP_DEV_DISABLE_AUTH:-false}

# Keep nginx-to-Uvicorn connections alive across normal polling intervals.
DTVP_UVICORN_KEEP_ALIVE_SECONDS=${DTVP_UVICORN_KEEP_ALIVE_SECONDS:-30}

echo "Serving frontend runtime configuration for DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH}"

# Run the boot wrapper so Uvicorn can bind before the full DTVP app imports.
exec /app/.venv/bin/uvicorn dtvp.boot:app \
    --host 0.0.0.0 \
    --port 8000 \
    --timeout-keep-alive "${DTVP_UVICORN_KEEP_ALIVE_SECONDS}" \
    --backlog 2048
