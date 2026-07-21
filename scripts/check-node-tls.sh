#!/bin/sh
set -eu

if [ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = "0" ]; then
    echo "Refusing to use Node.js with TLS certificate verification disabled." >&2
    echo "Unset NODE_TLS_REJECT_UNAUTHORIZED and configure a trusted CA instead." >&2
    exit 1
fi
