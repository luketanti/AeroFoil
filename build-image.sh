#!/usr/bin/env bash
set -euo pipefail

MODE=${1:-release}
VERSION=$(git describe --tags --always 2>/dev/null || echo dev)

if [ "$MODE" = "dev" ]; then
  VERSION="${VERSION}-dev"
  DOCKERFILE="Dockerfile.dev"
  TAG="aerofoil:dev"
else
  DOCKERFILE="Dockerfile"
  TAG="aerofoil:latest"
fi

docker build --build-arg AEROFOIL_VERSION="${VERSION}" -f "${DOCKERFILE}" -t "${TAG}" .

