#!/usr/bin/env bash
# Final stage only, using the existing official setup. Always import/verify the
# resulting proof against the original succinct receipt before using EVM bytes.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: bash risc0-groth16-local.sh WITNESS_DIRECTORY NEW_RESULT_DIRECTORY' >&2
  exit 2
fi
dcap_witness=$(cd "$1" && pwd -P)
test -s "$dcap_witness/input.json"
test -s "$dcap_witness/seal.r0"
test -s "$dcap_witness/manifest.json"
if [[ -e "$2" ]]; then echo 'Result directory must not exist' >&2; exit 2; fi
dcap_platform=${DCAP_R0_PLATFORM:-linux/arm64}
case "$dcap_platform" in
  linux/arm64) dcap_digest=55236d558d1e16e27f86f73237215c49f686521cab7652931c61c96d62cabcfc ;;
  linux/amd64) dcap_digest=7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331 ;;
  *) echo 'Only the two reviewed official platform manifests are allowed' >&2; exit 2 ;;
esac
dcap_image="risczero/risc0-groth16-prover@sha256:$dcap_digest"
mkdir "$2"
dcap_result=$(cd "$2" && pwd -P)
docker image inspect --format 'id={{.Id}} platform={{.Os}}/{{.Architecture}} digests={{json .RepoDigests}}' \
  "$dcap_image" > "$dcap_result/image.txt"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$dcap_image")" = "$dcap_platform"
cp "$dcap_witness/input.json" "$dcap_witness/seal.r0" "$dcap_witness/manifest.json" "$dcap_result/"
(cd "$dcap_result" && sha256sum input.json seal.r0 manifest.json > INPUT_SHA256SUMS)
docker version > "$dcap_result/docker-version.txt"
dcap_container="dcap-r0-final-$$"
dcap_stats_pid=''
cleanup() {
  if [[ -n "$dcap_stats_pid" ]]; then kill "$dcap_stats_pid" 2>/dev/null || true; wait "$dcap_stats_pid" 2>/dev/null || true; fi
  docker stop "$dcap_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
date -u +%FT%TZ > "$dcap_result/started.txt"
(
  while :; do
    date -u +%FT%TZ
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$dcap_container" 2>/dev/null || true
    sleep 10
  done
) > "$dcap_result/docker-resources.log" &
dcap_stats_pid=$!
set +e
docker run --rm --name "$dcap_container" --platform "$dcap_platform" \
  --network none --cap-drop=ALL --security-opt=no-new-privileges \
  --cpus 4 --memory 7g --memory-swap 7g --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --user "$(id -u):$(id -g)" \
  -v "$dcap_result:/mnt" -v "$dcap_witness/input.json:/mnt/input.json:ro" \
  "$dcap_image" 2>&1 | tee "$dcap_result/docker.log"
dcap_exit=${PIPESTATUS[0]}
set -e
printf '%s\n' "$dcap_exit" > "$dcap_result/exit.txt"
date -u +%FT%TZ > "$dcap_result/finished.txt"
cleanup
dcap_stats_pid=''
(cd "$dcap_result" && sha256sum -c INPUT_SHA256SUMS)
if [[ "$dcap_exit" != 0 ]]; then exit "$dcap_exit"; fi
test -s "$dcap_result/proof.json"
(cd "$dcap_result" && sha256sum proof.json > PROOF_SHA256SUMS)
echo 'Official Docker stage complete. Cryptographic import and fork verification are still required.'
