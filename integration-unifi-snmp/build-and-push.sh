#!/bin/bash
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
IMAGE_NAME="integration-unifi-snmp"
REGISTRY="ghcr.io/${GHCR_USER:-citus-cloud}"
VERSION="latest"
LOCAL_ONLY=false
NO_CACHE=""

# Parse arguments
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
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --local      Build locally without pushing to registry"
            echo "  --no-cache   Build without Docker cache"
            echo "  --version    Specify version tag (default: latest)"
            echo "  -h, --help   Show this help message"
            exit 0
            ;;
        *)
            # Assume it's a version if no flag
            VERSION="$1"
            shift
            ;;
    esac
done

# Check if required files exist
if [[ ! -f "$SCRIPT_DIR/Dockerfile" ]]; then
    echo "ERROR: Cannot find Dockerfile in: $SCRIPT_DIR"
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/lib/rapax.py" ]]; then
    echo "ERROR: Cannot find lib/rapax.py in: $SCRIPT_DIR/lib/"
    echo "Please ensure rapax.py symlink exists in the lib directory"
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/bin/unifi-device-snmp-pollerd.py" ]]; then
    echo "ERROR: Cannot find bin/unifi-device-snmp-pollerd.py in: $SCRIPT_DIR/bin/"
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/supervisord.conf" ]]; then
    echo "ERROR: Cannot find supervisord.conf in: $SCRIPT_DIR"
    exit 1
fi

echo "================================================"
echo "Rapax Unifi SNMP Integration - Build & Push"
echo "================================================"
echo "Image:    ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Registry: ${REGISTRY}"
echo "Build context: ${SCRIPT_DIR}"
if [[ -n "$NO_CACHE" ]]; then
    echo "Cache: disabled (--no-cache)"
fi
echo "================================================"

# Build the image
echo "Building image..."
docker build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "$SCRIPT_DIR"

# Also tag as latest if a specific version was provided
if [ "${VERSION}" != "latest" ]; then
    echo "Tagging as latest..."
    docker tag "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "${REGISTRY}/${IMAGE_NAME}:latest"
fi

if [ "$LOCAL_ONLY" = true ]; then
    echo "================================================"
    echo "Local build complete!"
    echo "================================================"
    echo "Image built:"
    echo "  ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    if [ "${VERSION}" != "latest" ]; then
        echo "  ${REGISTRY}/${IMAGE_NAME}:latest"
    fi
else
    # Authenticate to GHCR if credentials are available
    if [[ -n "${GHCR_TOKEN:-}" ]] && [[ -n "${GHCR_USER:-}" ]]; then
        echo "Authenticating to GHCR..."
        echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
    fi

    echo "================================================"
    echo "Pushing to registry..."
    echo "================================================"

    # Push to registry
    docker push "${REGISTRY}/${IMAGE_NAME}:${VERSION}"

    if [ "${VERSION}" != "latest" ]; then
        docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    fi

    echo "================================================"
    echo "Build and push complete!"
    echo "================================================"
    echo "Images pushed:"
    echo "  ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    if [ "${VERSION}" != "latest" ]; then
        echo "  ${REGISTRY}/${IMAGE_NAME}:latest"
    fi
fi
echo "================================================"
echo ""
echo "To run:"
echo "  docker run -d \\"
echo "    --name rapax-unifi-snmp \\"
echo "    --network rapax-dev-network \\"
echo "    -v /opt/rapax/logs:/opt/rapax/logs \\"
echo "    -v /opt/rapax/lib:/opt/rapax/lib:ro \\"
echo "    -v /opt/rapax/etc:/opt/rapax/etc:ro \\"
echo "    -e REDIS_HOST=rapax-redis \\"
echo "    -e REDIS_PORT=6379 \\"
echo "    -e COMPONENT_ID=unifi-snmp-1 \\"
echo "    ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo ""
echo "Environment Variables:"
echo "  REDIS_HOST              - Redis host (default: rapax-redis)"
echo "  REDIS_PORT              - Redis port (default: 6379)"
echo "  REDIS_PASSWORD          - Redis password (optional)"
echo "  SNMP_POLL_INTERVAL      - Polling interval in seconds (default: 60)"
echo "  SNMP_TIMEOUT            - SNMP timeout in ms (default: 1000)"
echo "  SNMP_WORKERS            - Number of worker threads (default: 5)"
echo "  CONFIG_UPDATE_INTERVAL  - Device refresh interval in seconds (default: 3600)"
echo "  COMPONENT_ID            - Unique identifier for this poller"
echo "  LOG_LEVEL               - Logging level (default: INFO)"
echo "================================================"
