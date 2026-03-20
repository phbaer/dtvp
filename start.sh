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

echo "Configuring frontend with DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH}, DTVP_FRONTEND_URL=${DTVP_FRONTEND_URL}, DTVP_DEFAULT_PROJECT_FILTER=${DTVP_DEFAULT_PROJECT_FILTER}"

# Replace placeholders in index.html
# We use a temp file to avoid issues with sed in-place
if [ -f "/app/frontend/dist/index.html" ]; then
    sed -e "s|\${DTVP_CONTEXT_PATH}|${DTVP_CONTEXT_PATH}|g" \
        -e "s|\${DTVP_FRONTEND_URL}|${DTVP_FRONTEND_URL}|g" \
        -e "s|\${DTVP_DEFAULT_PROJECT_FILTER}|${DTVP_DEFAULT_PROJECT_FILTER}|g" \
        /app/frontend/dist/index.html > /app/frontend/dist/index.html.tmp && \
    mv /app/frontend/dist/index.html.tmp /app/frontend/dist/index.html
else
    echo "Warning: /app/frontend/dist/index.html not found, skipping frontend configuration"
fi

# Run the application
exec /app/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
