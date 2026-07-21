#!/bin/sh
set -e

# Print the packaged project version before importing the application so it is
# present in the container logs even when application initialization fails.
AGENTYZER_VERSION=$(
    /app/.venv/bin/python -c 'from importlib.metadata import version; print(version("agentyzer"))' 2>/dev/null ||
    true
)
AGENTYZER_VERSION=${AGENTYZER_VERSION:-unknown}
AGENTYZER_BUILD_NUMBER=${AGENTYZER_BUILD_NUMBER:-unknown}
printf 'Agentyzer version: %s (build number: %s)\n' "${AGENTYZER_VERSION}" "${AGENTYZER_BUILD_NUMBER}"

exec /app/.venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000
