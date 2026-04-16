#!/bin/bash
# Rebuild PWA (WASM only) — no Docker rebuild needed
# With docker-compose.override.yml active, changes are live immediately.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v wasm-pack &> /dev/null; then
    echo "ERROR: wasm-pack not found. Install: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

echo "Building WASM..."
wasm-pack build crates/parolnet-wasm \
    --target web \
    --out-dir "$SCRIPT_DIR/pwa/pkg" \
    --release

rm -f pwa/pkg/.gitignore pwa/pkg/package.json pwa/pkg/README.md

# Generate SW integrity hashes
echo "Updating service worker integrity hashes..."
_hash() { sha256sum "$SCRIPT_DIR/pwa/$1" | cut -d' ' -f1; }
_patch() {
    local name="$1" hash="$2"
    sed -i "s|'$name':.*'[0-9a-f]*'|'$name':          '$hash'|" "$SCRIPT_DIR/pwa/sw.js"
}
_patch "app.js"          "$(_hash app.js)"
_patch "styles.css"      "$(_hash styles.css)"
_patch "crypto-store.js" "$(_hash crypto-store.js)"
_patch "index.html"      "$(_hash index.html)"

# Generate build info for dev
BUILD_DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"
BUILD_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
echo "window.BUILD_INFO={date:'dev $BUILD_DATE',dev:true};" > pwa/build-info.js

echo "PWA rebuilt ($(du -sh pwa/pkg/parolnet_wasm_bg.wasm | cut -f1)). Build: $BUILD_DATE ($BUILD_COMMIT). Refresh browser."
