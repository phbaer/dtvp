#!/bin/sh
set -e

# Default DTVP_CONTEXT_PATH to / if not set
DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH:-/}

# Ensure DTVP_CONTEXT_PATH starts with / and remove trailing slash if present (unless it is just /)
if [ "$DTVP_CONTEXT_PATH" != "/" ]; then
    DTVP_CONTEXT_PATH="/$(echo "$DTVP_CONTEXT_PATH" | sed 's|^/||' | sed 's|/$||')"
fi

echo "Starting frontend with DTVP_CONTEXT_PATH=${DTVP_CONTEXT_PATH}"

# Default DTVP_FRONTEND_URL to http://localhost:8000 if not set
DTVP_FRONTEND_URL=${DTVP_FRONTEND_URL:-http://localhost:8000}
echo "Using DTVP_FRONTEND_URL=${DTVP_FRONTEND_URL}"

# Replace placeholders in index.html
# We use a temp file to avoid issues with sed in-place on some busybox versions
sed -e "s|\${DTVP_CONTEXT_PATH}|${DTVP_CONTEXT_PATH}|g" \
    -e "s|\${DTVP_FRONTEND_URL}|${DTVP_FRONTEND_URL}|g" \
    /usr/share/nginx/html/index.html > /usr/share/nginx/html/index.html.tmp && mv /usr/share/nginx/html/index.html.tmp /usr/share/nginx/html/index.html

# Generate nginx.conf
if [ "$DTVP_CONTEXT_PATH" = "/" ]; then
    cat <<EOF > /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
else
    cat <<EOF > /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name localhost;
    # Keep root for fallback searches if needed, though alias handles most
    root /usr/share/nginx/html;
    index index.html;

    # Primary location for the context path
    location ${DTVP_CONTEXT_PATH}/ {
        alias /usr/share/nginx/html/;
        try_files \$uri \$uri/ /index.html;
    }

    # Redirect root to context path
    location = / { return 301 ${DTVP_CONTEXT_PATH}/; }
}
EOF
fi

echo "Nginx configuration generated:"
cat /etc/nginx/conf.d/default.conf

# Execute command
exec "$@"
