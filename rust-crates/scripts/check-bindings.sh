#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Check if contracts/ directory has uncommitted changes
if git diff --quiet -- contracts/; then
    echo "No changes to contracts/ directory detected. Skipping bindings check."
    exit 0
else
    echo "Changes detected in contracts/ directory. Checking if bindings are up to date..."

    # Regenerate bindings
    AUTOMATA_UPDATE_BINDINGS=1 cargo build -p automata-dcap-evm-bindings --quiet

    # Check if regenerated bindings differ from committed files
    if ! git diff --quiet -- crates/dcap-evm-bindings/src; then
        echo "❌ Bindings are out of date. Regenerated files differ from the repository." >&2
        echo "" >&2
        echo "Changes in contracts/ require updated bindings. Please run:" >&2
        echo "  AUTOMATA_UPDATE_BINDINGS=1 cargo build -p automata-dcap-evm-bindings" >&2
        echo "" >&2
        echo "Then commit the updated files in crates/dcap-evm-bindings/src/" >&2
        exit 1
    fi

    echo "✅ Bindings are up to date."
fi
