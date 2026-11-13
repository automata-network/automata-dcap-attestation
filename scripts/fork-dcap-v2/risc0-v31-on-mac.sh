#!/usr/bin/env bash
# Fresh 3.1 receipts only. Native Mac proving + pinned AMD64 Groth16 setup.
# No remote prover, credentials, deployments or public-chain transactions.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: bash risc0-v31-on-mac.sh SOURCE_COMMIT NEW_RESULT_DIR' >&2; exit 2; }
dcap_repo=$(cd "$(dirname "$0")/../.." && pwd -P)
source "$dcap_repo/rust-crates/libraries/zkvm/methods/docker/common.sh"
dcap_commit=$(git -C "$dcap_repo" rev-parse --verify "$1^{commit}")
[[ $(git -C "$dcap_repo" rev-parse HEAD) == "$dcap_commit" ]]
git -C "$dcap_repo" diff --quiet "$dcap_commit" -- rust-crates scripts evm/forge-test/assets/v2/fixtures
[[ $(uname -s) == Darwin ]] || { echo 'Run on the Mac, not the VM' >&2; exit 2; }
for tool in docker python3 shasum; do command -v "$tool" >/dev/null; done
[[ $(cargo risczero --version) == 'cargo-risczero 3.1.0' ]]
[[ $(r0vm --version) == 'risc0-r0vm 3.1.0' ]]
rustc +1.97.0 --version >/dev/null
rustc +1.88.0 --version >/dev/null
test ! -e "$2"
mkdir -p "$2"
dcap_result=$(cd "$2" && pwd -P)
mkdir "$dcap_result/inputs" "$dcap_result/programs" "$dcap_result/builds"
unset DEV_MODE RISC0_DEV_MODE BONSAI_API_KEY BONSAI_API_URL
export CARGO_BUILD_JOBS=4 RAYON_NUM_THREADS=4 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR="$dcap_result/target"
dcap_finish() {
  local status=$?
  trap - EXIT
  set +e
  printf '%s\n' "$status" > "$dcap_result/exit-status.txt"
  for mode in strict minimal; do
    for archive in "$dcap_result/builds/$mode"/dcap-risc0-official-pair.*/evidence.tar.gz; do
      [[ ! -f "$archive" ]] || cp "$archive" "$dcap_result/$mode-evidence.tar.gz"
    done
  done
  # No build trees, home directories, private keys or original source checkout.
  (set -e; cd "$dcap_result"; shopt -s nullglob
   files=(source-commit.txt exit-status.txt *.log inputs/* programs/* *-evidence.tar.gz
     strict/*.log minimal/*.log strict/*/*.log minimal/*/*.log
     strict/*/verified/* minimal/*/verified/*)
   repro_sha256 "${files[@]}" > RETURN_SHA256SUMS
   tar -czf return.tar.gz "${files[@]}" RETURN_SHA256SUMS)
  if [[ $? == 0 ]]; then
    echo "Return even on failure: $dcap_result/return.tar.gz"
  else
    echo "Packaging failed; preserve $dcap_result" >&2
    [[ $status != 0 ]] || status=1
  fi
  exit "$status"
}
printf '%s\n' "$dcap_commit" > "$dcap_result/source-commit.txt"
mkdir "$dcap_result/strict" "$dcap_result/minimal"
trap dcap_finish EXIT
cd "$dcap_repo"
dcap_docker="$dcap_repo/rust-crates/libraries/zkvm/methods/docker"
for mode in strict minimal; do
  mkdir "$dcap_result/builds/$mode"
  TMPDIR="$dcap_result/builds/$mode" bash "$dcap_docker/reproduce-official.sh" risc0 "$dcap_commit" "$mode" \
    2>&1 | tee "$dcap_result/$mode-build.log"
  pairs=("$dcap_result/builds/$mode"/dcap-risc0-official-pair.*)
  [[ ${#pairs[@]} == 1 ]]
  cp "${pairs[0]}/evidence.tar.gz" "$dcap_result/$mode-evidence.tar.gz"
  python3 "$dcap_docker/verify-returned.py" risc0 "$dcap_result/$mode-evidence.tar.gz" "$dcap_commit" \
    "$dcap_result/builds/$mode/verified" > "$dcap_result/$mode-evidence.log"
  cp "${pairs[0]}/a/results/risc0.elf" "$dcap_result/programs/$mode.elf"
  cp "${pairs[0]}/a/results/native-id.txt" "$dcap_result/programs/$mode.image-id"
done
! cmp -s "$dcap_result/programs/strict.image-id" "$dcap_result/programs/minimal.image-id"
cargo +1.97.0 build --locked --manifest-path rust-crates/Cargo.toml -p automata-dcap-zkvm --features risc0 \
  --example risc0_v2_execute --example risc0_v2_prove_local --example risc0_v2_compress_local \
  --example risc0_v2_groth16_handoff 2>&1 | tee "$dcap_result/host-build.log"
cargo +1.97.0 build --locked --manifest-path rust-crates/Cargo.toml -p dcap-rs --example v2_fixture \
  2>&1 | tee "$dcap_result/input-build.log"
dcap_bin="$CARGO_TARGET_DIR/debug/examples"
for fixture in ata-sgx-v3 ata-tdx-v4 v5; do
  "$dcap_bin/v2_fixture" export "evm/forge-test/assets/v2/fixtures/$fixture.json" "$dcap_result/inputs/$fixture.bin"
done
"$dcap_bin/v2_fixture" export evm/forge-test/assets/v2/fixtures/alibaba-v5.json \
  "$dcap_result/inputs/alibaba-v5.bin" --minimal
(cd "$dcap_result"; repro_sha256 programs/* inputs/* > inputs.sha256)
for mode in strict minimal; do
  args=()
  [[ "$mode" != minimal ]] || args+=(--minimal)
  program="$dcap_result/programs/$mode.elf"
  for fixture in ata-sgx-v3 ata-tdx-v4 v5; do
    run="$dcap_result/$mode/$fixture"
    mkdir "$run"
    input="$dcap_result/inputs/$fixture.bin"
    "$dcap_bin/risc0_v2_execute" "$program" "$input" ${args[@]+"${args[@]}"} --negative 2>&1 | tee "$run/execute.log"
    "$dcap_bin/risc0_v2_prove_local" "$program" "$input" "$run/composite.bin" ${args[@]+"${args[@]}"} 2>&1 | tee "$run/prove.log"
    "$dcap_bin/risc0_v2_compress_local" "$program" "$input" "$run/composite.bin" "$run/succinct" succinct ${args[@]+"${args[@]}"} \
      2>&1 | tee "$run/compress.log"
    "$dcap_bin/risc0_v2_groth16_handoff" prepare "$program" "$input" "$run/succinct/receipt.bin" "$run/witness" ${args[@]+"${args[@]}"} \
      2>&1 | tee "$run/prepare.log"
    (cd "$run/witness"; repro_sha256 input.json seal.r0 manifest.json > SHA256SUMS)
    bash scripts/fork-dcap-v2/risc0-groth16-mac.sh "$run/witness" "$run/docker" 2>&1 | tee "$run/docker-stage.log"
    "$dcap_bin/risc0_v2_groth16_handoff" import "$program" "$input" "$run/succinct/receipt.bin" \
      "$run/verified" "$run/docker/proof.json" ${args[@]+"${args[@]}"} 2>&1 | tee "$run/import.log"
  done
done
"$dcap_bin/risc0_v2_execute" "$dcap_result/programs/strict.elf" "$dcap_result/inputs/alibaba-v5.bin" --expect-reject \
  2>&1 | tee "$dcap_result/strict/alibaba-policy.log"
"$dcap_bin/risc0_v2_execute" "$dcap_result/programs/minimal.elf" "$dcap_result/inputs/alibaba-v5.bin" --minimal \
  2>&1 | tee "$dcap_result/minimal/alibaba-policy.log"
echo 'Both modes: reproducible builds, guest controls and real Groth16 receipts verified. Hoodi fork DCAP acceptance remains required.'
