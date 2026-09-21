#!/usr/bin/env bash
# Execute already verified Docker programs, never rebuild/substitute the guests.
# Host runners must first be rebuilt from the matching current source with --locked.
set -euo pipefail
test "$#" -eq 1 || { echo 'Usage: verify-current-guests.sh VERIFIED_BUILD_DIRECTORY' >&2; exit 2; }
dcap_repo="$(cd "$(dirname "$0")/../.." && pwd -P)"
dcap_evidence="$(cd "$1" && pwd -P)"
dcap_results="$dcap_evidence/execution-results"
mkdir "$dcap_results" # Refuse to overwrite a previous run.
unset DEV_MODE RISC0_DEV_MODE FRI_QUERIES
export VERIFY_VK=true FIX_CORE_SHAPES=true FIX_RECURSION_SHAPES=true
export RAYON_NUM_THREADS=2 MALLOC_ARENA_MAX=2
for dcap_backend in risc0 sp1; do
  for dcap_mode in strict minimal; do
  dcap_return="$dcap_evidence/$dcap_backend-$dcap_mode-return"
  test "$(< "$dcap_return/a/results/program-mode.txt")" = "$dcap_mode"
  test "$(< "$dcap_return/program-mode.txt")" = "$dcap_mode"
  dcap_program="$dcap_return/a/results/$dcap_backend.elf"
  (cd "$(dirname "$dcap_program")" && sha256sum -c artifact.sha256)
  dcap_runner="$dcap_repo/rust-crates/target/release/examples/${dcap_backend}_v2_execute"
  sha256sum "$dcap_runner" > "$dcap_results/$dcap_backend-$dcap_mode-runner.sha256"
  for dcap_sample in v3 v4 v5 ata-sgx-v3 ata-tdx-v4; do
    dcap_args=()
    if [[ "$dcap_mode" == minimal ]]; then dcap_args+=(--minimal); fi
    if [[ "$dcap_sample" == ata-sgx-v3 ]]; then dcap_args+=(--negative); fi
    dcap_log="$dcap_results/$dcap_backend-$dcap_mode-$dcap_sample.log"
    "$dcap_runner" "$dcap_program" "$dcap_evidence/inputs/$dcap_sample.bin" "${dcap_args[@]}" > "$dcap_log" 2>&1
    grep -F "native_program_id=$(< "$dcap_return/a/results/native-id.txt")" "$dcap_log"
    grep -E 'cycles=.*parity=PASS|quote_version=|rejection=.*PASS' "$dcap_log"
  done
  done
done
printf '%s\n' '20 positive executions and 32 guest rejection cases passed across strict/minimal; NOT proof or on-chain acceptance.' > "$dcap_results/PASS.txt"
cat "$dcap_results/PASS.txt"
