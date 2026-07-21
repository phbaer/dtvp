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

echo "Serving frontend runtime configuration for DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH}"

# Run the boot wrapper so Uvicorn can bind before the full DTVP app imports.
exec /app/.venv/bin/uvicorn dtvp.boot:app --host 0.0.0.0 --port 8000
