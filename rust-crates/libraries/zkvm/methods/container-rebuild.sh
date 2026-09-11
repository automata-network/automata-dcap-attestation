#!/usr/bin/env bash
# Historical cross-environment diagnostic, NOT the canonical release check.
# Use docker/reproduce-official.sh or docker/reproduce-pico.sh for paired builds.
# Invoked in the pinned Rust container, never on the host.
set -euo pipefail
test -f /.dockerenv
test "$#" -eq 1
repro_commit="$1"
if test -e /work/build; then
  echo "Build directory already exists; use a new container for a clean rebuild." >&2
  exit 1
fi
mkdir -p /work/source /work/results
git -c safe.directory=/source -C /source archive "$repro_commit" | tar -x -C /work/source
printf '%s\n' "$repro_commit" > /work/results/source-commit.txt
rustc -vV > /work/results/host-rustc.txt
RUSTUP_USE_CURL=1 rustup toolchain install 1.88.0 --profile minimal --no-self-update
RUSTUP_USE_CURL=1 rustup toolchain install nightly-2025-08-04 --profile minimal --component rust-src --no-self-update
rustup toolchain link succinct /opt/succinct
cd /work/source

# Every backend starts with a different empty target directory. No host Cargo
# cache, target directory, credentials or Docker socket is mounted here.
for repro_backend in risc0 sp1 pico; do
  mkdir -p "/work/build/$repro_backend/target"
  CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR="/work/build/$repro_backend/target" \
    cargo build --release --locked \
    --manifest-path "rust-crates/libraries/zkvm/methods/$repro_backend/Cargo.toml" \
    --target-dir "/work/build/$repro_backend/target" \
    2>&1 | tee "/work/results/$repro_backend-build.log"
  cp "rust-crates/libraries/zkvm/artifacts/v2.0/$repro_backend.elf" "/work/results/$repro_backend.elf"
  sha256sum "/work/results/$repro_backend.elf" | tee "/work/results/$repro_backend.sha256"
done
cp rust-crates/libraries/zkvm/artifacts/v2.0/risc0.image-id /work/results/
sha256sum rust-crates/libraries/zkvm/methods/{risc0/guest,sp1/program,pico/program}/Cargo.lock \
  > /work/results/guest-locks.sha256
echo "Compilation completed. Compare all hashes and native IDs; exit 0 is not a reproducibility pass."
