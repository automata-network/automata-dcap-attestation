#!/usr/bin/env bash
# RETIRED for compact V2: the v5 gnark transport, v5.0.0 circuit bundle and
# sp1_v2_import_gnark importer are incompatible with SP1 6.8.0 (the importer now
# fails closed). SP1 6.8.0 proves Groth16 through the full SDK pipeline:
#   sp1_v2_prove_local PROGRAM INPUT PROOF --kind groth16 [--minimal]
# Its .evm.json carries the SDK-encoded journal/proof/selector. Retained below
# solely as a historical resource-budget reference, not executable.
set -euo pipefail
echo 'Historical SP1 v5 gnark stage disabled for compact V2. Use the SP1 6.8.0 sp1_v2_prove_local runner; do not reuse old circuits, witnesses or transports.' >&2
exit 2
if [[ $# != 3 ]]; then
  echo 'Usage: bash sp1-gnark-local.sh VERIFIED_WITNESS_DIRECTORY OFFICIAL_CIRCUIT_DIRECTORY NEW_RESULT_DIRECTORY' >&2
  exit 2
fi
dcap_witness=$(cd "$1" && pwd -P)
dcap_circuit=$(cd "$2" && pwd -P)
test -s "$dcap_witness/witness.json"
test ! -e "$3"
dcap_image=sha256:ccb0c9a846f967999f737c672a2e4df9a6e6ddf194cc7e59cd94a0e4dae3a666
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$dcap_image")" = linux/arm64
test "$(< "$dcap_witness/image-id.txt")" = "$dcap_image"
(cd "$dcap_witness" && sha256sum -c SHA256SUMS)
# Fixed official setup, not a new keypair or a caller-supplied hash manifest.
(
  cd "$dcap_circuit"
  printf '%s\n' \
    'a4594c59bbc142f3b81c3ecb7f50a7c34bc9af7c4c444b5d48b795427e285913  groth16_vk.bin' \
    '2e287f249dd7f7d355cab08083a63daca4d0aa5d660b5f3ecebb102b7f21a7db  groth16_pk.bin' \
    'd5be4ba308f43e7541b0129c1d161d82029f471d434d1596e83edb046317e236  groth16_circuit.bin' \
    'f7f24d7268f03a142f904bb3274f403850a22a4270a1aaccee7570afb8c0d60d  groth16_witness.json' \
    '3b433dcf04c10a6c5b03e6610d6e3fc40acefe3c016497418965324a5c89f228  constraints.json' \
    | sha256sum -c -
)
node --input-type=module -e '
  import fs from "node:fs";
  const [actual, template] = process.argv.slice(1).map(p => JSON.parse(fs.readFileSync(p)));
  for (const field of ["vars", "felts", "exts"]) {
    if (!Array.isArray(actual[field]) || actual[field].length !== template[field].length)
      throw new Error("Witness layout differs from official setup: " + field);
  }
  if (actual.exts.some(v => !Array.isArray(v) || v.length !== 4)) throw new Error("Invalid extension-field layout");
  for (const field of ["vkey_hash", "committed_values_digest"])
    if (typeof actual[field] !== "string") throw new Error("Missing public input: " + field);
  console.log("Official witness layout matches; this is not cryptographic verification.");
' "$dcap_witness/witness.json" "$dcap_circuit/groth16_witness.json"
mkdir "$3"
dcap_result=$(cd "$3" && pwd -P)
docker image inspect --format 'id={{.Id}} platform={{.Os}}/{{.Architecture}}' "$dcap_image" > "$dcap_result/image.txt"
sha256sum "$dcap_witness/witness.json" > "$dcap_result/witness.sha256"
# Require 10 GiB available for three consecutive samples, retain a 1.5 GiB
# system-availability guard during proving, and never stop competing work.
dcap_stable=0
while [[ "$dcap_stable" -lt 3 ]]; do
  dcap_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  printf '%s available_kib=%s\n' "$(date -u +%FT%TZ)" "$dcap_available" >> "$dcap_result/preflight.log"
  if [[ "$dcap_available" -ge 10485760 ]]; then dcap_stable=$((dcap_stable + 1)); else dcap_stable=0; fi
  sleep 5
done
dcap_name="dcap-sp1-final-$$-$RANDOM"
dcap_watch=''
cleanup() {
  if [[ -n "$dcap_watch" ]]; then
    kill "$dcap_watch" 2>/dev/null || true
    wait "$dcap_watch" 2>/dev/null || true
    dcap_watch=''
  fi
  docker stop -t 2 "$dcap_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
: > "$dcap_result/gnark-proof.bin"
date -u +%FT%TZ > "$dcap_result/started.txt"
docker run --rm --pull never --name "$dcap_name" --platform linux/arm64 \
  --network none --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit 256 --cpus 1 --memory 11g --memory-swap 11g \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m --user "$(id -u):$(id -g)" \
  -e GOMAXPROCS=1 -e GOGC=50 -e GOMEMLIMIT=8GiB -v "$dcap_circuit:/circuit:ro" \
  -v "$dcap_witness/witness.json:/witness:ro" -v "$dcap_result/gnark-proof.bin:/output" \
  "$dcap_image" prove --system groth16 /circuit /witness /output \
  > "$dcap_result/docker.log" 2>&1 &
dcap_child=$!
(
  while kill -0 "$dcap_child" 2>/dev/null; do
    dcap_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    printf '%s available_kib=%s\n' "$(date -u +%FT%TZ)" "$dcap_available"
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$dcap_name" 2>/dev/null || true
    if [[ "$dcap_available" -lt 1572864 ]]; then
      printf 'available_kib=%s\n' "$dcap_available" > "$dcap_result/memory-guard.txt"
      docker stop -t 2 "$dcap_name" >/dev/null 2>&1 || true
      break
    fi
    sleep 3
  done
) > "$dcap_result/docker-resources.log" &
dcap_watch=$!
set +e
wait "$dcap_child"
dcap_exit=$?
set -e
date -u +%FT%TZ > "$dcap_result/finished.txt"
printf '%s\n' "$dcap_exit" > "$dcap_result/docker-exit.txt"
cleanup
if [[ -e "$dcap_result/memory-guard.txt" ]]; then exit 143; fi
if [[ "$dcap_exit" != 0 ]]; then exit "$dcap_exit"; fi
test -s "$dcap_result/gnark-proof.bin"
(cd "$dcap_result" && sha256sum gnark-proof.bin > OUTPUT_SHA256SUMS)
echo 'Official standalone Groth16 generation completed. Independent SDK import and EVM verification remain required.'
