#!/usr/bin/env bash
# RETIRED for compact V2: the v5 core/outer checkpoint protocol (and its
# sp1_v2_compress_local helper) is incompatible with SP1 6.8.0 and the helper
# now fails closed. Use the full SDK pipeline instead:
#   sp1_v2_prove_local PROGRAM INPUT PROOF --kind groth16 [--minimal]
# See rust-crates/libraries/zkvm/methods/sp1/README.md. No v6-resume workflow
# is accepted yet. Retained below solely as a historical resource-budget
# reference, not executable.
set -euo pipefail
echo 'Historical SP1 v5 outer-container handoff disabled for compact V2. Use the SP1 6.8.0 sp1_v2_prove_local runner; do not reuse old helpers, checkpoints or IDs.' >&2
exit 2
if [[ $# != 2 ]]; then
  echo 'Usage: bash sp1-outer-container.sh HANDOFF_DIRECTORY NEW_RESULT_DIRECTORY' >&2
  exit 2
fi
dcap_handoff=$(cd "$1" && pwd -P)
for dcap_file in helper program.elf input.bin compressed.bin SHA256SUMS; do
  test -s "$dcap_handoff/$dcap_file"
done
if [[ -e "$2" ]]; then echo 'Result directory must not exist' >&2; exit 2; fi
if command -v sha256sum >/dev/null; then dcap_sha=(sha256sum); else dcap_sha=(shasum -a 256); fi
(cd "$dcap_handoff" && "${dcap_sha[@]}" -c SHA256SUMS)
dcap_image=ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$dcap_image")" = linux/arm64
# The container is capped at 14 GiB. Leave at least 2 GiB for its Docker VM;
# this is not permission to consume all RAM on a concurrently busy machine.
dcap_docker_memory=$(docker info --format '{{.MemTotal}}')
if [[ "$dcap_docker_memory" -lt 17179869184 ]]; then
  echo 'Docker needs at least 16 GiB assigned; use a larger/otherwise idle machine.' >&2
  exit 2
fi
mkdir "$2"
dcap_result=$(cd "$2" && pwd -P)
docker image inspect --format 'id={{.Id}} platform={{.Os}}/{{.Architecture}} digests={{json .RepoDigests}}' "$dcap_image" > "$dcap_result/image.txt"
docker version > "$dcap_result/docker-version.txt"
dcap_container="dcap-sp1-outer-$$"
dcap_stats_pid=''
cleanup() {
  if [[ -n "$dcap_stats_pid" ]]; then
    kill "$dcap_stats_pid" 2>/dev/null || true
    wait "$dcap_stats_pid" 2>/dev/null || true
    dcap_stats_pid=''
  fi
  docker stop -t 2 "$dcap_container" >/dev/null 2>&1 || true
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
docker run --rm --name "$dcap_container" --pull never --platform linux/arm64 \
  --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit 256 --cpus 2 --memory 14g --memory-swap 14g \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m --user "$(id -u):$(id -g)" \
  -e RAYON_NUM_THREADS=2 -e MALLOC_ARENA_MAX=2 -e RUST_LOG=info \
  -e VERIFY_VK=true -e FIX_CORE_SHAPES=true -e FIX_RECURSION_SHAPES=true \
  -v "$dcap_handoff:/handoff:ro" -v "$dcap_result:/result" \
  --entrypoint /handoff/helper "$dcap_image" \
  /handoff/program.elf /handoff/input.bin /handoff/compressed.bin /result/outer outer \
  2>&1 | tee "$dcap_result/docker.log"
dcap_exit=${PIPESTATUS[0]}
set -e
printf '%s\n' "$dcap_exit" > "$dcap_result/exit.txt"
date -u +%FT%TZ > "$dcap_result/finished.txt"
cleanup
if [[ "$dcap_exit" != 0 ]]; then exit "$dcap_exit"; fi
test -s "$dcap_result/outer/outer.bin"
(cd "$dcap_result" && "${dcap_sha[@]}" outer/outer.bin outer/compressed.bin > OUTPUT_SHA256SUMS)
echo 'Outer checkpoint verified and saved. This is NOT a Groth16 proof or fork acceptance.'
