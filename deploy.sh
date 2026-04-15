#!/bin/bash
# ParolNet Deploy Script
# Builds WASM, rebuilds Docker container, restarts service
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ParolNet Deploy ==="
echo ""

# Step 1: Build WASM
echo "[1/2] Building WASM module..."
if ! command -v wasm-pack &> /dev/null; then
    echo "ERROR: wasm-pack not found. Install: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

wasm-pack build crates/parolnet-wasm \
    --target web \
    --out-dir "$SCRIPT_DIR/pwa/pkg" \
    --release

# Clean wasm-pack extras
rm -f pwa/pkg/.gitignore pwa/pkg/package.json pwa/pkg/README.md

echo "WASM built: $(du -sh pwa/pkg/parolnet_wasm_bg.wasm | cut -f1)"
echo ""

# Step 2: Rebuild Docker image (multi-stage: compiles relay server + bundles with nginx)
echo "[2/2] Rebuilding Docker image and restarting..."
BUILD_DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"
BUILD_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
BUILD_VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
echo "Build: v$BUILD_VERSION $BUILD_COMMIT ($BUILD_DATE)"
docker compose build --no-cache \
    --build-arg "BUILD_DATE=$BUILD_DATE" \
    --build-arg "BUILD_COMMIT=$BUILD_COMMIT" \
    --build-arg "BUILD_VERSION=$BUILD_VERSION"

# Restart container
docker compose down
docker compose up -d

# Cleanup dangling images and build cache
echo "Cleaning up old Docker artifacts..."
docker image prune -f
docker builder prune -f

echo ""
echo "=== Deploy complete ==="
echo "Site: http://localhost:1411"
echo ""
