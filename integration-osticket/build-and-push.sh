#!/bin/bash
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
IMAGE_NAME="integration-osticket"
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
            echo "Usage: $0 [OPTIONS] [VERSION]"
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
echo "================================================"
echo "Rapax OSTicket Integration - Build & Push"
echo "================================================"
echo "Validating required files..."

REQUIRED_FILES=(
    "Dockerfile"
    "requirements.txt"
    "osticket-agentd.py"
    "entrypoint.sh"
    "healthcheck.sh"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$SCRIPT_DIR/$file" ]]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo "ERROR: Missing required files:"
    for file in "${MISSING_FILES[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

echo "All required files present"
echo ""

echo "================================================"
echo "Build Configuration"
echo "================================================"
echo "Image:         ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Registry:      ${REGISTRY}"
echo "Build context: ${SCRIPT_DIR}"
echo "Dockerfile:    ${SCRIPT_DIR}/Dockerfile"
echo "================================================"
echo ""

# Build the image
echo "Building image..."
docker build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "$SCRIPT_DIR"

echo ""
echo "Image built successfully"
echo ""

# Also tag as latest if a specific version was provided
if [ "${VERSION}" != "latest" ]; then
    echo "Tagging as latest..."
    docker tag "${REGISTRY}/${IMAGE_NAME}:${VERSION}" "${REGISTRY}/${IMAGE_NAME}:latest"
    echo "Tagged as latest"
    echo ""
fi

if [ "$LOCAL_ONLY" = true ]; then
    echo "================================================"
    echo "✓ Local build complete!"
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

    echo ""
    echo "================================================"
    echo "✓ Build and push complete!"
    echo "================================================"
    echo "Images pushed:"
    echo "  ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    if [ "${VERSION}" != "latest" ]; then
        echo "  ${REGISTRY}/${IMAGE_NAME}:latest"
    fi
fi
echo "================================================"
echo ""
echo "To run the container:"
echo ""
echo "  docker run -d \\"
echo "    --name rapax-integration-osticket \\"
echo "    --network rapax-dev-network \\"
echo "    -v /opt/rapax/lib:/opt/rapax/lib:ro \\"
echo "    -v /opt/rapax/etc:/opt/rapax/etc:ro \\"
echo "    -e RAPAXHOME=/opt/rapax \\"
echo "    -e RAPAX_HOME=/opt/rapax \\"
echo "    -e DAEMON_INTERVAL=60 \\"
echo "    ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo ""
echo "================================================"
