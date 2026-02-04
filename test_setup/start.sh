#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Starting Dependency-Track environment..."

if command -v podman-compose &> /dev/null; then
    COMPOSE_CMD="podman-compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: neither podman-compose nor docker-compose found."
    exit 1
fi

echo "Using: $COMPOSE_CMD"

$COMPOSE_CMD -f "$DIR/docker-compose.yml" up -d postgres dtrack-apiserver dtrack-frontend

echo "Waiting for Dependency-Track to initialize..."
# We run the init script as a container attaching to the network
$COMPOSE_CMD -f "$DIR/docker-compose.yml" up init-dtrack

echo "Environment is running."
