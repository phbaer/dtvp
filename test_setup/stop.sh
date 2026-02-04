#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
if command -v podman-compose &> /dev/null; then
    COMPOSE_CMD="podman-compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: neither podman-compose nor docker-compose found."
    exit 1
fi

echo "Using: $COMPOSE_CMD"

$COMPOSE_CMD -f "$DIR/docker-compose.yml" down -v
echo "Environment stopped and volumes removed."
