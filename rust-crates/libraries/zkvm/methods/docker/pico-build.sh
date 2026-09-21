#!/usr/bin/env bash
# Run only inside the pinned Pico build image, with a read-only source archive.
set -euo pipefail
test -f /.dockerenv
test ! -e /work/build
test ! -e /work/source
mkdir -p /work/source /work/results
tar -xf /input/source.tar -C /work/source
cd /work/source
sha256sum /input/source.tar > /work/results/source-archive.sha256
sha256sum rust-crates/libraries/zkvm/methods/pico/{Cargo.lock,program/Cargo.lock} > /work/results/locks-before.sha256
rustc -vV > /work/results/host-rustc.txt
rustc +nightly-2025-08-04 -vV > /work/results/guest-rustc.txt
sha256sum /input/pico-build.sh > /work/results/build-script.sha256
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/work/build/pico/target \
  cargo build --release --locked \
  --manifest-path rust-crates/libraries/zkvm/methods/pico/Cargo.toml \
  --target-dir /work/build/pico/target
sha256sum --check /work/results/locks-before.sha256
for mode in strict minimal; do
  cp "rust-crates/libraries/zkvm/artifacts/v2.0/pico-$mode.elf" "/work/results/pico-$mode.elf"
  sha256sum "/work/results/pico-$mode.elf" > "/work/results/pico-$mode.sha256"
done
