#!/usr/bin/env bash
# Real local proofs only. Does not invoke a remote prover, deploy, or register IDs.
set -euo pipefail
[[ "$#" -eq 4 || "$#" -eq 5 ]] || { echo 'Usage: prove-current.sh risc0|sp1 VERIFIED_BUILD_DIRECTORY strict|minimal FIXTURE_NAME [ATTEMPT_LABEL]' >&2; exit 2; }
dcap_backend="$1"
case "$dcap_backend" in risc0|sp1) ;; *) exit 2 ;; esac
case "$3" in strict|minimal) ;; *) exit 2 ;; esac
dcap_mode="$3"
case "$4" in v3|v4|v5|ata-sgx-v3|ata-tdx-v4) ;; *) exit 2 ;; esac
dcap_repo="$(cd "$(dirname "$0")/../.." && pwd -P)"
dcap_base="$(cd "$2" && pwd -P)"
test -s "$dcap_base/execution-results/PASS.txt"
dcap_run="$dcap_base/$dcap_backend-$dcap_mode-$4-proof"
if [[ "$#" -eq 5 ]]; then
  [[ "$5" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || { echo 'Invalid attempt label' >&2; exit 2; }
  dcap_run="$dcap_run-$5"
fi
dcap_return="$dcap_base/$dcap_backend-$dcap_mode-return"
test "$(< "$dcap_return/a/results/program-mode.txt")" = "$dcap_mode"
test "$(< "$dcap_return/program-mode.txt")" = "$dcap_mode"
mkdir "$dcap_run" # Never overwrite proof checkpoints.
dcap_program="$dcap_return/a/results/$dcap_backend.elf"
dcap_input="$dcap_base/inputs/$4.bin"
dcap_args=()
if [[ "$dcap_mode" == minimal ]]; then dcap_args+=(--minimal); fi
dcap_runner="$dcap_repo/rust-crates/target/release/examples/${dcap_backend}_v2_prove_local"
dcap_output="$dcap_run/proof.bin"
test -x "$dcap_runner" && test -s "$dcap_input"
(cd "$(dirname "$dcap_program")" && sha256sum -c artifact.sha256)
sha256sum "$dcap_program" "$dcap_input" "$dcap_runner" > "$dcap_run/inputs.sha256"
unset DEV_MODE RISC0_DEV_MODE FRI_QUERIES SP1_DEV_MODE DCAP_SP1_SHARD_SIZE
export VERIFY_VK=true FIX_CORE_SHAPES=true FIX_RECURSION_SHAPES=true
export RAYON_NUM_THREADS=4 MALLOC_ARENA_MAX=2 RUST_LOG=info
if [[ "$dcap_backend" == sp1 ]]; then
  unset TRACE_GEN_WORKERS CHECKPOINTS_CHANNEL_CAPACITY RECORDS_AND_TRACES_CHANNEL_CAPACITY
fi
# This limits virtual address space only. The watchdog separately bounds RSS and
# preserves at least 1.5 GiB host headroom; it may stop this proof, never unrelated work.
date -u +%FT%TZ > "$dcap_run/started.txt"
node "$dcap_repo/scripts/fork-dcap-v2/watch-proof.mjs" "${dcap_backend}_v2_prove" \
  "$dcap_output" "$dcap_run/exit.txt" > "$dcap_run/resources.log" 2>&1 &
dcap_watch=$!
trap 'kill "$dcap_watch" 2>/dev/null || true; wait "$dcap_watch" 2>/dev/null || true' EXIT
set +e
(ulimit -v 25165824; exec /usr/bin/time -v "$dcap_runner" "$dcap_program" "$dcap_input" "$dcap_output" "${dcap_args[@]}") > "$dcap_run/prove.log" 2>&1
dcap_exit=$?
set -e
printf '%s\n' "$dcap_exit" > "$dcap_run/exit.txt"
date -u +%FT%TZ > "$dcap_run/finished.txt"
if [[ "$dcap_exit" != 0 ]]; then tail -20 "$dcap_run/prove.log"; exit "$dcap_exit"; fi
"$dcap_runner" "$dcap_program" "$dcap_input" "$dcap_output" --verify "${dcap_args[@]}" > "$dcap_run/readback.log" 2>&1
grep -F "native_program_id=$(< "$dcap_return/a/results/native-id.txt")" "$dcap_run/readback.log"
sha256sum "$dcap_output" > "$dcap_run/proof.sha256"
printf '%s\n' 'CORE/COMPOSITE_PROOF_AND_READBACK_PASS; EVM compression and on-chain verification NOT_RUN' > "$dcap_run/PASS.txt"
cat "$dcap_run/PASS.txt"
