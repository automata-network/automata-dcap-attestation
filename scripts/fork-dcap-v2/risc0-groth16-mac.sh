#!/usr/bin/env bash
# Run ONLY the official final Groth16 stage on the Mac/AMD64 Docker machine.
# Returned JSON is not accepted until the Rust importer and real fork verify it.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo 'Usage: bash risc0-groth16-mac.sh WITNESS_DIR NEW_RESULT_DIR' >&2
  exit 2
fi
dcap_witness=$(cd "$1" && pwd -P)
if [[ -e "$2" ]]; then echo 'Result directory must not exist' >&2; exit 2; fi
test -s "$dcap_witness/input.json"
test -s "$dcap_witness/seal.r0"
test -s "$dcap_witness/SHA256SUMS"
(cd "$dcap_witness" && shasum -a 256 -c SHA256SUMS)
mkdir -p "$2"
dcap_result=$(cd "$2" && pwd -P)
dcap_image=${DCAP_R0_GROTH16_IMAGE:-risczero/risc0-groth16-prover:v2025-04-03.1}
case "$dcap_image" in
  risczero/risc0-groth16-prover:v2025-04-03.1|risczero/risc0-groth16-prover@sha256:*) ;;
  *) echo 'Use the pinned SDK image, not a different circuit/setup' >&2; exit 2 ;;
esac
docker pull --platform linux/amd64 "$dcap_image" 2>&1 | tee "$dcap_result/pull.log"
dcap_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$dcap_image")
case "$dcap_digest" in
  risczero/risc0-groth16-prover@sha256:*) ;;
  *) echo 'Unable to resolve immutable image reference' >&2; exit 2 ;;
esac
docker image inspect --format 'id={{.Id}} platform={{.Os}}/{{.Architecture}} digests={{json .RepoDigests}}' "$dcap_digest" > "$dcap_result/image.txt"
docker version > "$dcap_result/docker-version.txt"
docker info --format 'os={{.OSType}} arch={{.Architecture}} cpus={{.NCPU}} memory={{.MemTotal}}' > "$dcap_result/docker-resources.txt"
cp "$dcap_witness/input.json" "$dcap_witness/seal.r0" "$dcap_witness/manifest.json" "$dcap_result/"
date -u +%FT%TZ > "$dcap_result/started.txt"
dcap_container="dcap-r0-groth16-$$"
trap 'docker stop "$dcap_container" >/dev/null 2>&1 || true' INT TERM
set +e
docker run --rm --name "$dcap_container" --platform linux/amd64 \
  --network none --cap-drop=ALL --security-opt=no-new-privileges \
  --cpus "${DCAP_PROOF_CPUS:-4}" --memory "${DCAP_PROOF_MEMORY:-7g}" \
  -v "$dcap_result:/mnt" "$dcap_digest" 2>&1 | tee "$dcap_result/docker.log"
dcap_exit=${PIPESTATUS[0]}
set -e
printf '%s\n' "$dcap_exit" > "$dcap_result/exit.txt"
date -u +%FT%TZ > "$dcap_result/finished.txt"
dcap_files=(manifest.json image.txt docker-version.txt docker-resources.txt pull.log docker.log started.txt finished.txt exit.txt)
if [[ -s "$dcap_result/proof.json" ]]; then dcap_files+=(proof.json); fi
(cd "$dcap_result" && shasum -a 256 "${dcap_files[@]}" > RETURN_SHA256SUMS)
tar -czf "$dcap_result/return.tar.gz" -C "$dcap_result" "${dcap_files[@]}" RETURN_SHA256SUMS
echo "Return even on failure: $dcap_result/return.tar.gz"
if [[ "$dcap_exit" != 0 ]]; then exit "$dcap_exit"; fi
test -s "$dcap_result/proof.json"
echo 'Docker proof generated; local cryptographic import and fork acceptance remain required.'
