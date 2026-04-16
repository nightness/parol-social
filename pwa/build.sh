#!/bin/bash
# Build ParolNet PWA
#
# This script:
# 1. Parses optional authority key arguments
# 2. Builds the WASM module with wasm-pack (passing keys via env vars to build.rs)
# 3. Generates pwa/network-config.js with the network identity
# 4. Copies the output to pwa/pkg/
#
# The result is a fully self-contained PWA that can be:
#    - Served from any static file host
#    - Distributed as a ZIP file
#    - Hosted on IPFS
#    - Served from a Tor hidden service
#    - Placed on a USB drive
#
# After first load, the PWA works entirely offline.
# If the source site disappears, installed copies keep working.
#
# Usage:
#   ./build.sh                                      # Dev build (placeholder keys)
#   ./build.sh --pubkeys KEY1,KEY2,KEY3             # Production build
#   ./build.sh --pubkeys KEY1,KEY2 --threshold 2    # With custom threshold
#   ./build.sh --pubkeys KEY1,KEY2 --network-name "MyNet" --bootstrap-relays URL1,URL2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Defaults ───────────────────────────────────────────────────
PUBKEYS=""
NETWORK_NAME="ParolNet Dev"
BOOTSTRAP_RELAYS=""
THRESHOLD="2"

# ── Parse arguments ────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pubkeys)
            PUBKEYS="$2"
            shift 2
            ;;
        --network-name)
            NETWORK_NAME="$2"
            shift 2
            ;;
        --bootstrap-relays)
            BOOTSTRAP_RELAYS="$2"
            shift 2
            ;;
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --pubkeys KEY1,KEY2,...      Comma-separated 64-char hex Ed25519 pubkeys"
            echo "  --network-name NAME          Network display name (default: 'ParolNet Dev')"
            echo "  --bootstrap-relays URL1,...   Comma-separated bootstrap relay URLs"
            echo "  --threshold N                Authority threshold (default: 2)"
            echo "  --help                       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Set env vars for Rust build.rs ─────────────────────────────
if [ -n "$PUBKEYS" ]; then
    export AUTHORITY_PUBKEYS="$PUBKEYS"
    export AUTHORITY_THRESHOLD="$THRESHOLD"
    echo "Building with custom authority keys (threshold=$THRESHOLD)"
else
    echo "Building with dev-mode placeholder keys"
fi

# ── Check wasm-pack ────────────────────────────────────────────
echo "Building ParolNet WASM module..."
cd "$PROJECT_ROOT"

if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Install it with:"
    echo "  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

# ── Build WASM ─────────────────────────────────────────────────
wasm-pack build crates/parolnet-wasm \
    --target web \
    --out-dir "$SCRIPT_DIR/pkg" \
    --release

# Remove unnecessary files from pkg
rm -f "$SCRIPT_DIR/pkg/.gitignore"
rm -f "$SCRIPT_DIR/pkg/package.json"
rm -f "$SCRIPT_DIR/pkg/README.md"

# ── Bundle JS + SW hashes + build-info ─────────────────────────
if ! node -e "require('esbuild')" 2>/dev/null; then
    echo "Installing esbuild..."
    (cd "$PROJECT_ROOT" && npm install --save-dev esbuild)
fi
node "$SCRIPT_DIR/build.mjs"

# ── Compute network ID (SHA-256 of sorted pubkeys) ────────────
compute_network_id() {
    local keys="$1"
    if [ -z "$keys" ]; then
        # Dev defaults: 0x01*32, 0x02*32, 0x03*32 — already sorted
        printf '%064x%064x%064x' 0x0101010101010101010101010101010101010101010101010101010101010101 0x0202020202020202020202020202020202020202020202020202020202020202 0x0303030303030303030303030303030303030303030303030303030303030303 | xxd -r -p | sha256sum | cut -d' ' -f1
    else
        # Sort keys, concatenate binary, hash
        echo "$keys" | tr ',' '\n' | sort | tr -d '\n' | xxd -r -p | sha256sum | cut -d' ' -f1
    fi
}

NETWORK_ID=$(compute_network_id "$PUBKEYS")

# ── Build pubkeys JS array ─────────────────────────────────────
build_pubkeys_js() {
    local keys="$1"
    if [ -z "$keys" ]; then
        keys="0101010101010101010101010101010101010101010101010101010101010101,0202020202020202020202020202020202020202020202020202020202020202,0303030303030303030303030303030303030303030303030303030303030303"
    fi
    local result=""
    local first=true
    IFS=',' read -ra KEY_ARRAY <<< "$keys"
    for key in "${KEY_ARRAY[@]}"; do
        key=$(echo "$key" | tr -d '[:space:]')
        if [ "$first" = true ]; then
            first=false
        else
            result+=","
        fi
        result+=$'\n'"    '${key}'"
    done
    echo "$result"
}

PUBKEYS_JS=$(build_pubkeys_js "$PUBKEYS")

# ── Build bootstrap relays JS array ───────────────────────────
build_relays_js() {
    local relays="$1"
    if [ -z "$relays" ]; then
        echo ""
        return
    fi
    local result=""
    local first=true
    IFS=',' read -ra RELAY_ARRAY <<< "$relays"
    for relay in "${RELAY_ARRAY[@]}"; do
        relay=$(echo "$relay" | tr -d '[:space:]')
        if [ "$first" = true ]; then
            first=false
        else
            result+=","
        fi
        result+=$'\n'"    '${relay}'"
    done
    echo "$result"
}

RELAYS_JS=$(build_relays_js "$BOOTSTRAP_RELAYS")

# ── Generate network-config.js ─────────────────────────────────
cat > "$SCRIPT_DIR/network-config.js" << CONFIGEOF
// ParolNet Network Configuration (generated by build.sh)
// DO NOT EDIT — this file is overwritten during production builds

export const NETWORK_NAME = '${NETWORK_NAME}';
export const NETWORK_ID = '${NETWORK_ID}';
export const AUTHORITY_PUBKEYS = [${PUBKEYS_JS}
];
export const AUTHORITY_THRESHOLD = ${THRESHOLD};
export const BOOTSTRAP_RELAYS = [${RELAYS_JS}
];
CONFIGEOF

echo ""
echo "PWA built successfully!"
echo "  Network: ${NETWORK_NAME}"
echo "  Network ID: ${NETWORK_ID}"
echo ""
echo "Files in $SCRIPT_DIR/:"
ls -la "$SCRIPT_DIR/"
echo ""
echo "To serve locally:"
echo "  cd $SCRIPT_DIR && python3 -m http.server 8080"
echo ""
echo "To distribute:"
echo "  1. Upload the entire pwa/ directory to any static host"
echo "  2. Or zip it: cd $SCRIPT_DIR && zip -r parolnet-pwa.zip ."
echo "  3. Or IPFS: ipfs add -r $SCRIPT_DIR"
echo ""
echo "After first visit, the app works entirely offline."
echo "If the host disappears, installed copies keep working."
