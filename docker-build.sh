#!/usr/bin/env bash
#
# docker-build.sh - Linux/macOS helper
#
# This script aligns with CLIProxyAPI's interactive Docker flow.
# 1) Run with pre-built image (recommended)
# 2) Build local image from source and run

set -euo pipefail

ensure_runtime_files() {
  if [[ ! -f "config.yaml" ]]; then
    if [[ -f "config.example.yaml" ]]; then
      cp config.example.yaml config.yaml
      echo "Created config.yaml from config.example.yaml"
    else
      echo "Warning: config.example.yaml not found. Please create config.yaml manually."
    fi
  fi

  mkdir -p auths logs
}

resolve_version() {
  local version="dev"
  local commit="none"
  local build_date
  build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if command -v git >/dev/null 2>&1; then
    version="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
    commit="$(git rev-parse --short HEAD 2>/dev/null || echo "none")"
  fi

  echo "${version}|${commit}|${build_date}"
}

echo "Please select an option:"
echo "1) Run using Pre-built Image (Recommended)"
echo "2) Build from Source and Run (For Developers)"
read -r -p "Enter choice [1-2]: " choice

ensure_runtime_files

case "${choice}" in
  1)
    echo "--- Running with Pre-built Image ---"
    docker compose up -d --remove-orphans --no-build
    echo "Services are starting from remote image."
    echo "Run 'docker compose logs -f antigravity-403-plugin' to see logs."
    ;;
  2)
    echo "--- Building from Source and Running ---"
    meta="$(resolve_version)"
    VERSION="${meta%%|*}"
    rest="${meta#*|}"
    COMMIT="${rest%%|*}"
    BUILD_DATE="${rest#*|}"

    echo "Building with the following info:"
    echo "  Version: ${VERSION}"
    echo "  Commit: ${COMMIT}"
    echo "  Build Date: ${BUILD_DATE}"
    echo "----------------------------------------"

    export PLUGIN_IMAGE="obeginners/antigravity-403-plugin:local"

    echo "Building the Docker image..."
    docker compose build \
      --build-arg VERSION="${VERSION}" \
      --build-arg COMMIT="${COMMIT}" \
      --build-arg BUILD_DATE="${BUILD_DATE}"

    echo "Starting the services..."
    docker compose up -d --remove-orphans --pull never

    echo "Build complete. Services are starting."
    echo "Run 'docker compose logs -f antigravity-403-plugin' to see logs."
    ;;
  *)
    echo "Invalid choice. Please enter 1 or 2."
    exit 1
    ;;
esac
