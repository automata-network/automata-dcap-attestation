#!/bin/bash
# Clean deployment cache to force re-download on next build

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$PROJECT_ROOT/crates/network-registry/deployment/cache"

echo "Cleaning deployment cache..."

if [ -d "$CACHE_DIR" ]; then
    rm -rf "$CACHE_DIR"
    echo "✓ Removed deployment cache at: $CACHE_DIR"
else
    echo "⚠ Cache directory does not exist: $CACHE_DIR"
fi

echo ""
echo "Next build will re-download deployment files from version.toml URLs."
