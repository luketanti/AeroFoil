#!/usr/bin/env bash
set -euo pipefail

MODE=${1:-release}
VERSION=$(git describe --tags --always 2>/dev/null || echo dev)

if [ "$MODE" = "dev" ]; then
  VERSION="${VERSION}-dev"
  DOCKERFILE="Dockerfile.dev"
  TAG="ownfoil:dev"
else
  DOCKERFILE="Dockerfile"
  TAG="ownfoil:latest"
fi

docker build --build-arg OWNFOIL_VERSION="${VERSION}" -f "${DOCKERFILE}" -t "${TAG}" .
