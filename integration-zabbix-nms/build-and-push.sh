#!/bin/bash
#
# Build and push integration-zabbix-nms container
#

set -e

# Configuration
IMAGE_NAME="integration-zabbix-nms"
REGISTRY="ghcr.io/${GHCR_USER:-citus-cloud}"
VERSION="${VERSION:-latest}"
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
NO_CACHE=""
LOCAL_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --local)
            LOCAL_ONLY=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        -h|--help)
            echo "Build and push integration-zabbix-nms container"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-cache    Force fresh build"
            echo "  --local       Build only, don't push"
            echo "  --version     Tag with specific version (default: latest)"
            echo "  -h, --help    Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=========================================="
echo "Building integration-zabbix-nms"
echo "=========================================="
echo "Image: ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Build dir: ${BUILD_DIR}"
echo ""

# Build
docker build $NO_CACHE \
    -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" \
    -f "${BUILD_DIR}/Dockerfile" \
    "${BUILD_DIR}"

if [ "$LOCAL_ONLY" = true ]; then
    echo ""
    echo "Local build complete (--local specified, not pushing)"
    exit 0
fi

# Push
echo ""
echo "Pushing to registry..."

    # Authenticate to GHCR if credentials are available
    if [[ -n "${GHCR_TOKEN:-}" ]] && [[ -n "${GHCR_USER:-}" ]]; then
        echo "Authenticating to GHCR..."
        echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
    fi
docker push "${REGISTRY}/${IMAGE_NAME}:${VERSION}"

# Tag as latest if version specified
if [ "$VERSION" != "latest" ]; then
    docker tag "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "${REGISTRY}/${IMAGE_NAME}:latest"
    docker push "${REGISTRY}/${IMAGE_NAME}:latest"
fi

echo ""
echo "=========================================="
echo "Build and push complete"
echo "=========================================="
