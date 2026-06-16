#!/bin/bash

################################################################################
# Build and Push Script for Rapax MariaDB Data Exporter
################################################################################

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_CONTEXT="$SCRIPT_DIR/.."
IMAGE_NAME="integration-mariadb-exporter"
REGISTRY="ghcr.io/${GHCR_USER:-citus-cloud}"
VERSION="latest"
NO_CACHE=""
LOCAL_ONLY=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-cache     Force fresh build (no Docker cache)"
    echo "  --local        Build only, don't push to registry"
    echo "  --version X.Y.Z  Tag with specific version"
    echo "  --help         Show this help message"
    echo ""
    exit 0
}

# Parse arguments
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
        --help|-h)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Rapax MariaDB Exporter Build${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Image:    ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Context:  $BUILD_CONTEXT"
echo "Options:  ${NO_CACHE:-none}"
echo ""

# Build
echo -e "${YELLOW}Building image...${NC}"
docker build \
    $NO_CACHE \
    -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" \
    -f "$SCRIPT_DIR/Dockerfile" \
    "$BUILD_CONTEXT"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Tag as latest if version specified
if [ "$VERSION" != "latest" ]; then
    echo -e "${YELLOW}Tagging as latest...${NC}"
    docker tag "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "${REGISTRY}/${IMAGE_NAME}:latest"
fi

# Push
if [ "$LOCAL_ONLY" = false ]; then
    # Authenticate to GHCR if credentials are available
    if [[ -n "${GHCR_TOKEN:-}" ]] && [[ -n "${GHCR_USER:-}" ]]; then
        echo "Authenticating to GHCR..."
        echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
    fi

    echo ""
    echo -e "${YELLOW}Pushing to registry...${NC}"
    docker push "${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    if [ "$VERSION" != "latest" ]; then
        docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    fi
    echo -e "${GREEN}Push successful!${NC}"
else
    echo ""
    echo -e "${YELLOW}Skipping push (--local specified)${NC}"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
echo ""
echo "To run locally:"
echo "  docker run -d --name rapax-mariadb-exporter \\"
echo "    --network rapax-dev-network \\"
echo "    -v /opt/rapax/logs:/opt/rapax/logs \\"
echo "    -v /opt/rapax/etc:/opt/rapax/etc:ro \\"
echo "    ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo ""
