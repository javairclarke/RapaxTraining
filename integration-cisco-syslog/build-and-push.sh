#!/bin/bash
# Build and push Cisco Syslog Integration container
# Usage: ./build-and-push.sh [--local] [--no-cache] [--version X.Y.Z]

set -e

# Configuration
IMAGE_NAME="integration-cisco-syslog"
REGISTRY="ghcr.io/${GHCR_USER:-citus-cloud}"
DEFAULT_VERSION="latest"

# Parse arguments
LOCAL_ONLY=false
NO_CACHE=""
VERSION="$DEFAULT_VERSION"

while [[ $# -gt 0 ]]; do
    case $1 in
        --local)
            LOCAL_ONLY=true
            shift
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--local] [--no-cache] [--version X.Y.Z]"
            echo ""
            echo "Options:"
            echo "  --local      Build only, don't push to registry"
            echo "  --no-cache   Build without cache"
            echo "  --version    Tag with specific version (default: latest)"
            echo "  --help       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "================================================"
echo "Building Cisco Syslog Integration"
echo "================================================"
echo "Image: ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Build context: ${REPO_ROOT}"
echo "Local only: ${LOCAL_ONLY}"
echo "No cache: ${NO_CACHE:-no}"
echo "================================================"

# Build the image
echo ""
echo "Building Docker image..."
docker build \
    ${NO_CACHE} \
    -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${REPO_ROOT}"

# Tag as latest if version specified
if [ "$VERSION" != "latest" ]; then
    echo "Tagging as latest..."
    docker tag "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "${REGISTRY}/${IMAGE_NAME}:latest"
fi

echo ""
echo "Build complete: ${REGISTRY}/${IMAGE_NAME}:${VERSION}"

# Authenticate to GHCR if credentials are available
if [[ -n "${GHCR_TOKEN:-}" ]] && [[ -n "${GHCR_USER:-}" ]]; then
    echo "Authenticating to GHCR..."
    echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
fi

# Push to registry unless local only
if [ "$LOCAL_ONLY" = false ]; then
    echo ""
    echo "Pushing to registry..."
    docker push "${REGISTRY}/${IMAGE_NAME}:${VERSION}"

    if [ "$VERSION" != "latest" ]; then
        docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    fi

    echo ""
    echo "Push complete!"
else
    echo ""
    echo "Local build only - not pushing to registry"
fi

echo ""
echo "================================================"
echo "Done!"
echo "================================================"
