#!/usr/bin/env bash
# Run the exact returned SP1 guest using a packaged ARM64 Linux host helper.
# No guest build, network prover, circuit changes or on-chain transactions.
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: sp1-core-on-mac.sh HANDOFF NEW_RESULT_DIRECTORY' >&2; exit 2; }
dcap_handoff=$(cd "$1" && pwd -P)
[[ ! -e "$2" ]] || { echo 'Result directory already exists' >&2; exit 2; }
if command -v sha256sum >/dev/null; then dcap_sha=(sha256sum); else dcap_sha=(shasum -a 256); fi
(cd "$dcap_handoff" && "${dcap_sha[@]}" -c SHA256SUMS)
dcap_image=ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
[[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$dcap_image") == linux/arm64 ]]
[[ $(docker info --format '{{.MemTotal}}') -ge 17179869184 ]] || {
  echo 'Assign at least 16 GiB to Docker and use an otherwise idle machine.' >&2; exit 2;
}
mkdir "$2"
dcap_result=$(cd "$2" && pwd -P)
dcap_container="dcap-sp1-core-$$"
dcap_stats_pid=''
cleanup() {
  if [[ -n "$dcap_stats_pid" ]]; then
    kill "$dcap_stats_pid" 2>/dev/null || true
    wait "$dcap_stats_pid" 2>/dev/null || true
    dcap_stats_pid=''
  fi
  docker stop -t 2 "$dcap_container" >/dev/null 2>&1 || true
}
finish() {
  dcap_status=$?
  trap - EXIT
  cleanup
  printf '%s\n' "$dcap_status" > "$dcap_result/exit.txt"
  date -u +%FT%TZ > "$dcap_result/finished.txt"
  # Create outside the archived directory so its mtime does not change during
  # traversal (GNU tar otherwise returns 1 and masks the actual prover status).
  dcap_archive=$(mktemp "$dcap_result/../dcap-core-return.XXXXXX")
  COPYFILE_DISABLE=1 tar -czf "$dcap_archive" -C "$dcap_result" .
  mv "$dcap_archive" "$dcap_result/return.tar.gz"
  echo "Return on success or failure: $dcap_result/return.tar.gz"
  exit "$dcap_status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
date -u +%FT%TZ > "$dcap_result/started.txt"
cp "$dcap_handoff/SHA256SUMS" "$dcap_result/handoff.sha256"
docker version > "$dcap_result/docker-version.txt"
docker image inspect "$dcap_image" > "$dcap_result/image-inspect.json"
(
  while :; do
    date -u +%FT%TZ
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$dcap_container" 2>/dev/null || true
    sleep 10
  done
) > "$dcap_result/resources.log" &
dcap_stats_pid=$!
docker run --rm --pull never --name "$dcap_container" --platform linux/arm64 \
  --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit 256 --cpus 4 --memory 10g --memory-swap 10g \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m --user "$(id -u):$(id -g)" \
  -e RAYON_NUM_THREADS=4 -e MALLOC_ARENA_MAX=2 -e RUST_LOG=info \
  -e DCAP_SP1_SHARD_SIZE=131072 \
  -e VERIFY_VK=true -e FIX_CORE_SHAPES=true -e FIX_RECURSION_SHAPES=true \
  -e TRACE_GEN_WORKERS=1 -e CHECKPOINTS_CHANNEL_CAPACITY=1 -e RECORDS_AND_TRACES_CHANNEL_CAPACITY=1 \
  -v "$dcap_handoff:/handoff:ro" -v "$dcap_result:/result" \
  --entrypoint /bin/bash "$dcap_image" -c '
    set -euo pipefail
    /handoff/helper /handoff/program.elf /handoff/input.bin /result/proof.bin 2>&1 | tee /result/prove.log
    /handoff/helper /handoff/program.elf /handoff/input.bin /result/proof.bin --verify 2>&1 | tee /result/readback.log
    grep -Fx "native_program_id=$(cat /handoff/native-id.txt)" /result/readback.log
    cd /result
    sha256sum proof.bin > proof.sha256
    printf "%s\n" "REAL_CORE_PROOF_AND_READBACK_PASS; EVM compression and on-chain acceptance NOT_RUN" > PASS.txt
  ' 2>&1 | tee "$dcap_result/session.log"
