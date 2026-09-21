#!/usr/bin/env bash
# Host orchestrator: two fresh containers, one immutable image/source, no host
# compiler/cache mounts. Output equality is necessary, not a real-proof check.
set -euo pipefail
if test "$#" -ne 2; then
  echo 'usage: bash reproduce-pico.sh COMMIT IMAGE_ID_OR_DIGEST' >&2
  exit 2
fi
repro_commit="$1"
repro_image="$2"
if ! [[ "$repro_image" =~ ^sha256:[0-9a-f]{64}$ || "$repro_image" =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo 'Refusing a mutable image tag; pass an image ID or repository@sha256 digest.' >&2
  exit 2
fi
repro_scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repro_repo="$(git -C "$repro_scripts" rev-parse --show-toplevel)"
repro_commit="$(git -C "$repro_repo" rev-parse --verify "${repro_commit}^{commit}")"
test "$(docker image inspect --format '{{.Architecture}}' "$repro_image")" = aarch64 || \
  test "$(docker image inspect --format '{{.Architecture}}' "$repro_image")" = arm64
repro_work="$(mktemp -d /tmp/dcap-pico-docker-pair.XXXXXX)"
echo "Results: $repro_work"
git -C "$repro_repo" archive --format=tar --output="$repro_work/source.tar" "$repro_commit"
cp "$repro_scripts/pico-build.sh" "$repro_work/pico-build.sh"
printf '%s\n' "$repro_commit" > "$repro_work/source-commit.txt"
docker image inspect "$repro_image" > "$repro_work/image-inspect.json"
for repro_run in a b; do
  repro_container="dcap-pico-pair-${repro_work##*.}-$repro_run"
  docker run --name "$repro_container" --platform linux/arm64 \
    --cpus=4 --memory=8g --pids-limit=512 --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --mount "type=bind,source=$repro_work/source.tar,target=/input/source.tar,readonly" \
    --mount "type=bind,source=$repro_work/pico-build.sh,target=/input/pico-build.sh,readonly" \
    --entrypoint /bin/bash "$repro_image" /input/pico-build.sh \
    2>&1 | tee "$repro_work/$repro_run.log"
  docker cp "$repro_container:/work/results" "$repro_work/$repro_run"
done
for repro_mode in strict minimal; do
  cmp "$repro_work/a/pico-$repro_mode.elf" "$repro_work/b/pico-$repro_mode.elf"
  sha256sum "$repro_work/a/pico-$repro_mode.elf" "$repro_work/b/pico-$repro_mode.elf"
done
cmp "$repro_work/a/guest-rustc.txt" "$repro_work/b/guest-rustc.txt"
cmp "$repro_work/a/locks-before.sha256" "$repro_work/b/locks-before.sha256"
echo 'Container-to-container bytes match. Compute native IDs and run guest/proof checks before release.'
