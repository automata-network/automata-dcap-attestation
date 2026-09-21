#!/usr/bin/env bash
# Official RISC Zero/SP1 Docker paths. Requires an AMD64 Docker execution
# environment (including Docker Desktop + Rosetta). No binfmt installation,
# privileged containers, or Docker socket mounts.
set -euo pipefail
if test "$#" -lt 2 || test "$#" -gt 3; then
  echo 'usage: bash reproduce-official.sh risc0|sp1 COMMIT [strict|minimal]' >&2
  exit 2
fi
repro_backend="$1"
repro_commit="$2"
repro_mode="${3:-strict}"
case "$repro_mode" in strict|minimal) ;; *) echo 'Expected strict or minimal mode' >&2; exit 2 ;; esac
repro_scripts="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$repro_scripts/common.sh"
# Host metadata only. Do NOT replace either official image's own Cargo version.
export RUSTUP_TOOLCHAIN=1.88.0
case "$repro_backend" in
  risc0)
    repro_image='risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3'
    repro_manifest='rust-crates/libraries/zkvm/methods/risc0/guest/Cargo.toml'
    test "$(cargo risczero --version)" = 'cargo-risczero 3.0.3'
    test "$(r0vm --version)" = 'risc0-r0vm 3.0.3'
    [[ "$(rustc +risc0 --version)" == 'rustc 1.88.0'* ]] || {
      echo 'SDK 3.0.3 also queries the local rzup Rust version to choose codegen flags; select RISC Zero Rust 1.88.' >&2
      exit 2
    }
    repro_cli="$(command -v cargo-risczero)"
    ;;
  sp1)
    export RUSTUP_TOOLCHAIN=1.96.0
    repro_image='ghcr.io/succinctlabs/sp1:v6.8.0@sha256:6df25c1a71451b51488534fb94a495ffe456c05921f79c4bcb8ccafe2810870c'
    repro_manifest='rust-crates/libraries/zkvm/methods/sp1/program/Cargo.toml'
    repro_cli="${SP1_CARGO_PROVE:-$(command -v cargo-prove || true)}"
    test -x "$repro_cli" || { echo 'Set SP1_CARGO_PROVE to the installed v6.8.0 cargo-prove binary.' >&2; exit 2; }
    repro_cli="$(repro_physical_file "$repro_cli")"
    [[ "$("$repro_cli" prove --version)" == 'cargo-prove sp1 (58c4aea'* ]] || {
      echo 'Expected the SP1 v6.8.0 CLI (58c4aea); do not substitute another release.' >&2
      exit 2
    }
    ;;
  *) echo 'Unsupported backend; use reproduce-pico.sh for Pico.' >&2; exit 2 ;;
esac
test -z "${RISC0_SKIP_BUILD:-}${SP1_SKIP_PROGRAM_BUILD:-}"
[[ "$(cargo --version)" == "cargo $RUSTUP_TOOLCHAIN "* ]] || {
  echo "Install host metadata tools: rustup toolchain install $RUSTUP_TOOLCHAIN --profile minimal" >&2
  exit 2
}
if test -n "${REPRO_SOURCE_ARCHIVE:-}"; then
  repro_archive="$(repro_physical_file "$REPRO_SOURCE_ARCHIVE")"
  [[ "$repro_commit" =~ ^[0-9a-f]{40}$ ]]
  test "$(git get-tar-commit-id < "$repro_archive")" = "$repro_commit"
else
  repro_repo="$(git -C "$repro_scripts" rev-parse --show-toplevel)"
  repro_commit="$(git -C "$repro_repo" rev-parse --verify "${repro_commit}^{commit}")"
fi
REPRO_DOCKER_BIN="$(repro_physical_file "$(command -v docker)")"
export REPRO_DOCKER_BIN
repro_work="$(mktemp -d "${TMPDIR:-/tmp}/dcap-$repro_backend-official-pair.XXXXXX")"
repro_work="$(cd -P -- "$repro_work" && pwd -P)"
echo "Results: $repro_work"
repro_finish() {
  local repro_status=$?
  trap - EXIT
  set +e
  printf '%s\n' "$repro_status" > "$repro_work/exit-status.txt"
  # Explicit allowlist: no source/target trees, caches, home directory or secrets.
  (
    cd "$repro_work" || exit 1
    shopt -s nullglob
    local repro_evidence=(*.log *.txt *.sha256 *.json scripts)
    local repro_run
    for repro_run in a b; do
      if test -d "$repro_run/results"; then repro_evidence+=("$repro_run/results"); fi
    done
    tar -czf evidence.tar.gz "${repro_evidence[@]}"
  )
  if test "$?" -eq 0; then
    echo "Return this file (including on failure): $repro_work/evidence.tar.gz"
  else
    echo "Evidence packaging failed; preserve the Results directory: $repro_work" >&2
  fi
  exit "$repro_status"
}
trap repro_finish EXIT
mkdir "$repro_work/scripts"
cp "$repro_scripts/common.sh" "$repro_scripts/reproduce-official.sh" \
  "$repro_scripts/docker-no-cache.sh" "$repro_work/scripts/"
printf '%s\n' "$repro_commit" > "$repro_work/source-commit.txt"
printf '%s\n' "$repro_mode" > "$repro_work/program-mode.txt"
printf '%s\n' "$repro_image" > "$repro_work/image-reference.txt"
if test -n "${REPRO_SOURCE_ARCHIVE:-}"; then
  cp "$repro_archive" "$repro_work/source.tar"
else
  git -C "$repro_repo" archive --format=tar --output="$repro_work/source.tar" "$repro_commit"
fi
(
  cd "$repro_work"
  repro_sha256 source.tar scripts/*.sh > inputs.sha256
)
{
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  uname -smr
  if command -v sw_vers >/dev/null 2>&1; then sw_vers; fi
  docker version
  docker info --format 'os={{.OSType}} arch={{.Architecture}} cpus={{.NCPU}} memory={{.MemTotal}}'
  cargo --version
  rustc --version
  if test "$repro_backend" = risc0; then
    cargo risczero --version
    r0vm --version
    rustc +risc0 --version
    rzup show
  else
    "$repro_cli" prove --version
  fi
} > "$repro_work/environment.txt" 2>&1
repro_sha256 "$repro_cli" > "$repro_work/host-tools.sha256"
if test "$repro_backend" = risc0; then
  repro_sha256 "$(command -v r0vm)" >> "$repro_work/host-tools.sha256"
fi
docker run --rm --platform linux/amd64 --cap-drop=ALL \
  --security-opt=no-new-privileges --entrypoint /bin/true "$repro_image" \
  2>&1 | tee "$repro_work/preflight.log"
docker image inspect "$repro_image" > "$repro_work/image-inspect.json"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$repro_image")" = linux/amd64
mkdir "$repro_work/bin"
cp "$repro_scripts/docker-no-cache.sh" "$repro_work/bin/docker"
chmod +x "$repro_work/bin/docker"
export NO_COLOR=1 CARGO_TERM_COLOR=never
for repro_run in a b; do
  repro_source="$repro_work/$repro_run/source"
  repro_results="$repro_work/$repro_run/results"
  mkdir -p "$repro_source" "$repro_results"
  tar -xf "$repro_work/source.tar" -C "$repro_source"
  (
    cd "$repro_source"
    repro_sha256 "${repro_manifest%Cargo.toml}Cargo.lock" > "$repro_results/lock.sha256"
    export CARGO_TARGET_DIR="$repro_source/target"
    # SDK CLIs perform host-side metadata discovery, not host guest compilation.
    # Resolve only the existing lock, then prevent metadata from changing it.
    cargo metadata --locked --format-version 1 --manifest-path "$repro_manifest" > "$repro_results/metadata.json"
    export CARGO_NET_OFFLINE=true
    export PATH="$repro_work/bin:$PATH"
    if test "$repro_backend" = risc0; then
      export RISC0_DOCKER_CONTAINER_TAG='r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3'
      cargo risczero build --manifest-path "$repro_manifest"
      # Official SDK 3.x packs the built user ELF with its kernel. Keep the
      # combined program, not just the raw user ELF with a different image ID.
      repro_guest=guest
      if test "$repro_mode" = minimal; then repro_guest=guest-minimal; fi
      cp "target/riscv32im-risc0-zkvm-elf/docker/$repro_guest.bin" "$repro_results/risc0.elf"
      r0vm --elf "$repro_results/risc0.elf" --id > "$repro_results/native-id.stdout"
    else
      export SP1_DOCKER_IMAGE="$repro_image"
      repro_guest=dcap-sp1-guest-v2
      if test "$repro_mode" = minimal; then repro_guest=dcap-sp1-guest-v2-minimal; fi
      (
        cd "${repro_manifest%/Cargo.toml}"
        "$repro_cli" prove build --docker --tag v6.8.0 --locked --no-docker-cache \
          --binaries "$repro_guest" \
          --workspace-directory "$repro_source" \
          --output-directory "$repro_source/repro-output" --elf-name sp1.elf
      )
      cp repro-output/sp1.elf "$repro_results/sp1.elf"
      VERIFY_VK=true FIX_CORE_SHAPES=true FIX_RECURSION_SHAPES=true \
        "$repro_cli" prove vkey --elf "$repro_results/sp1.elf" > "$repro_results/native-id.stdout"
    fi
    test -s "$repro_results/$repro_backend.elf"
    printf '%s\n' "$repro_mode" > "$repro_results/program-mode.txt"
    repro_native_id "$repro_results/native-id.stdout" > "$repro_results/native-id.txt"
    repro_sha256 --check "$repro_results/lock.sha256"
    (
      cd "$repro_results"
      repro_sha256 "$repro_backend.elf" > artifact.sha256
    )
  ) 2>&1 | tee "$repro_work/$repro_run.log"
done
cmp "$repro_work/a/results/lock.sha256" "$repro_work/b/results/lock.sha256"
cmp "$repro_work/a/results/$repro_backend.elf" "$repro_work/b/results/$repro_backend.elf"
cmp "$repro_work/a/results/native-id.txt" "$repro_work/b/results/native-id.txt"
printf '%s\n' 'PASS: independent official Docker builds match in bytes and native ID.' > "$repro_work/comparison.txt"
echo 'Official Docker builds match in bytes and native ID. Guest regression and real-proof checks remain required.'
