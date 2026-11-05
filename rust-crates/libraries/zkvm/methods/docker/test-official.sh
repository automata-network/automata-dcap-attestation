#!/usr/bin/env bash
# Tests orchestration with FAKE tools/artifacts, not Docker or cryptography.
set -euo pipefail
test_scripts="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$test_scripts/common.sh"
test_repo="$(git -C "$test_scripts" rev-parse --show-toplevel)"
test_commit="$(git -C "$test_repo" rev-parse HEAD)"
test_work="$(mktemp -d /tmp/dcap-official-harness-test.XXXXXX)"
mkdir "$test_work/bin" "$test_work/physical-tmp"
ln -s "$test_work/physical-tmp" "$test_work/linked-tmp"
for test_tool in cargo cargo-risczero cargo-prove rustc r0vm rzup docker; do
  cp "$test_scripts/test-fixtures/mock-tool.sh" "$test_work/bin/$test_tool"
  chmod +x "$test_work/bin/$test_tool"
done
git -C "$test_repo" archive --format=tar --output="$test_work/source.tar" HEAD \
  rust-crates/libraries/zkvm/methods/risc0/guest/Cargo.lock \
  rust-crates/libraries/zkvm/methods/sp1/program/Cargo.lock

# Exercise macOS's shasum fallback without requiring GNU coreutils there.
test_sha="$(repro_sha256 "$test_work/source.tar")"
test_fallback="$(
  command() {
    if test "${1:-}" = -v && test "${2:-}" = sha256sum; then return 1; fi
    builtin command "$@"
  }
  repro_sha256 "$test_work/source.tar"
)"
test "$test_sha" = "$test_fallback"

test_case() {
  local test_backend="$1" test_mode="$2" test_expected="$3" test_status=0
  local test_log="$test_work/$test_backend-$test_mode.log" test_results
  PATH="$test_work/bin:$PATH" TMPDIR="$test_work/linked-tmp" \
    REPRO_SOURCE_ARCHIVE="$test_work/source.tar" SP1_CARGO_PROVE="$test_work/bin/cargo-prove" \
    MOCK_MODE="$test_mode" bash "$test_scripts/reproduce-official.sh" "$test_backend" "$test_commit" "${4:-strict}" \
    > "$test_log" 2>&1 || test_status=$?
  if test "$test_status" -ne "$test_expected"; then
    sed -n '1,160p' "$test_log"
    echo "Unexpected status for $test_backend/$test_mode: $test_status" >&2
    exit 1
  fi
  test_results="$(sed -n 's/^Results: //p' "$test_log")"
  [[ "$test_results" == "$test_work/physical-tmp/"* ]]
  test "$(< "$test_results/exit-status.txt")" = "$test_expected"
  test -s "$test_results/evidence.tar.gz"
  tar -tzf "$test_results/evidence.tar.gz" > "$test_work/archive-list.txt"
  if grep -Eq '(^|/)(source|target|bin)/|source\.tar$' "$test_work/archive-list.txt"; then
    echo 'Evidence archive unexpectedly includes build trees' >&2
    exit 1
  fi
  if test "$test_expected" = 0; then
    test -s "$test_results/comparison.txt"
    test "$(< "$test_results/a/results/native-id.txt")" = \
      0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    cmp "$test_results/a/results/native-id.txt" "$test_results/b/results/native-id.txt"
    (cd "$test_results/a/results" && repro_sha256 --check artifact.sha256)
  else
    test ! -e "$test_results/comparison.txt"
  fi
}
test_case risc0 pass 0
test_case risc0 pass 0 minimal
test_case sp1 pass 0
test_case sp1 mismatch 1
test_case sp1 fail 42
test_case sp1 bad_id 1
test_case sp1 lock_change 1
echo '8 orchestration/portability cases passed using FAKE tools. No Docker builds or proofs verified.'
echo "Retained test evidence: $test_work"
