#!/usr/bin/env bash
# Run an exported handoff without cloning/pushing a development branch.
set -euo pipefail
case "${1:-}" in risc0|sp1) ;; *) echo 'usage: bash run-handoff.sh risc0|sp1' >&2; exit 2 ;; esac
test "$#" -eq 1
repro_handoff="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$repro_handoff"
source ./common.sh
repro_sha256 --check MANIFEST.sha256
export REPRO_SOURCE_ARCHIVE="$repro_handoff/source.tar"
bash ./reproduce-official.sh "$1" "$(< source-commit.txt)" 2>&1 | tee "$1-session.log"
