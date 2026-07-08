#!/bin/sh
set -e

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

echo "Configuring frontend with DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH}, DTVP_FRONTEND_URL=${DTVP_FRONTEND_URL}, DTVP_DEFAULT_PROJECT_FILTER=${DTVP_DEFAULT_PROJECT_FILTER}, DTVP_ATTRIBUTION_AGE_FILTER_DAYS=${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}, DTVP_DEV_DISABLE_AUTH=${DTVP_DEV_DISABLE_AUTH}"

# Render frontend runtime config from the immutable build template on every
# container start. Rendering index.html in place is not restart-safe because
# placeholders disappear after the first boot.
INDEX_TEMPLATE="/app/frontend/dist/index.html.template"
INDEX_TARGET="/app/frontend/dist/index.html"

if [ -f "${INDEX_TEMPLATE}" ]; then
    sed -e "s|\${DTVP_CONTEXT_PATH}|${DTVP_CONTEXT_PATH}|g" \
        -e "s|\${DTVP_FRONTEND_URL}|${DTVP_FRONTEND_URL}|g" \
        -e "s|\${DTVP_DEV_DISABLE_AUTH}|${DTVP_DEV_DISABLE_AUTH}|g" \
        -e "s|\${DTVP_DEFAULT_PROJECT_FILTER}|${DTVP_DEFAULT_PROJECT_FILTER}|g" \
        -e "s|\${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}|${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}|g" \
        "${INDEX_TEMPLATE}" > "${INDEX_TARGET}.tmp" && \
    mv "${INDEX_TARGET}.tmp" "${INDEX_TARGET}"
elif [ -f "${INDEX_TARGET}" ]; then
    echo "Warning: ${INDEX_TEMPLATE} not found, rendering existing index.html once"
    sed -e "s|\${DTVP_CONTEXT_PATH}|${DTVP_CONTEXT_PATH}|g" \
        -e "s|\${DTVP_FRONTEND_URL}|${DTVP_FRONTEND_URL}|g" \
        -e "s|\${DTVP_DEV_DISABLE_AUTH}|${DTVP_DEV_DISABLE_AUTH}|g" \
        -e "s|\${DTVP_DEFAULT_PROJECT_FILTER}|${DTVP_DEFAULT_PROJECT_FILTER}|g" \
        -e "s|\${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}|${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}|g" \
        "${INDEX_TARGET}" > "${INDEX_TARGET}.tmp" && \
    mv "${INDEX_TARGET}.tmp" "${INDEX_TARGET}"
else
    echo "Warning: ${INDEX_TARGET} not found, skipping frontend configuration"
fi

# Run the boot wrapper so Uvicorn can bind before the full DTVP app imports.
exec /app/.venv/bin/uvicorn dtvp.boot:app --host 0.0.0.0 --port 8000
