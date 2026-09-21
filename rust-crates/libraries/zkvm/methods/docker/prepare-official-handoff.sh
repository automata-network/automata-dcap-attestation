#!/usr/bin/env bash
# Export committed guest sources plus the reviewed, possibly uncommitted harness.
# No Git mutation, SDK installation, Docker access or remote upload.
set -euo pipefail
test "$#" -eq 1 || { echo 'usage: bash prepare-official-handoff.sh COMMIT' >&2; exit 2; }
repro_scripts="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$repro_scripts/common.sh"
repro_repo="$(git -C "$repro_scripts" rev-parse --show-toplevel)"
repro_commit="$(git -C "$repro_repo" rev-parse --verify "$1^{commit}")"
repro_export="$(mktemp -d "${TMPDIR:-/tmp}/dcap-official-handoff.XXXXXX")"
repro_export="$(cd -P -- "$repro_export" && pwd -P)"
repro_bundle="$repro_export/dcap-official-handoff"
mkdir "$repro_bundle"
git -C "$repro_repo" archive --format=tar --output="$repro_bundle/source.tar" "$repro_commit"
printf '%s\n' "$repro_commit" > "$repro_bundle/source-commit.txt"
cp "$repro_scripts/common.sh" "$repro_scripts/docker-no-cache.sh" \
  "$repro_scripts/reproduce-official.sh" "$repro_scripts/run-handoff.sh" \
  "$repro_scripts/README.md" "$repro_bundle/"
(
  cd "$repro_bundle"
  repro_sha256 source.tar source-commit.txt README.md ./*.sh > MANIFEST.sha256
)
tar -czf "$repro_export/dcap-official-handoff.tar.gz" -C "$repro_export" dcap-official-handoff
repro_sha256 "$repro_export/dcap-official-handoff.tar.gz"
echo "Transfer to the Mac/AMD64 worker: $repro_export/dcap-official-handoff.tar.gz"
