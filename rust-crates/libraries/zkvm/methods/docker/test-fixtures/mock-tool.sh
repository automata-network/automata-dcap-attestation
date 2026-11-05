#!/usr/bin/env bash
# Harness tests ONLY. These bytes are not zkVM programs, IDs or proofs.
set -euo pipefail
mock_tool="$(basename "$0")"
mock_id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mock_program() {
  test ! -e "$CARGO_TARGET_DIR"
  test "$CARGO_TARGET_DIR" = "$1/target"
  test "$(cd -P "$1" && pwd -P)" = "$1"
  [[ "${RUSTUP_TOOLCHAIN:-}" == 1.88.0 || "${RUSTUP_TOOLCHAIN:-}" == 1.96.0 ]]
  if test "${MOCK_MODE:-pass}" = fail; then exit 42; fi
  mkdir -p "$CARGO_TARGET_DIR" "$(dirname "$2")"
  printf '%s\n' 'NOT A REAL ZKVM PROGRAM' > "$2"
  if test "${MOCK_MODE:-pass}" = mismatch && [[ "$1" == */b/source ]]; then
    printf '%s\n' 'DIFFERENT B ARTIFACT' >> "$2"
  fi
  if test "${MOCK_MODE:-pass}" = lock_change; then
    printf '\n' >> "$1/rust-crates/libraries/zkvm/methods/sp1/program/Cargo.lock"
  fi
}
case "$mock_tool" in
  cargo)
    case "$1" in
      --version) echo "cargo ${RUSTUP_TOOLCHAIN:-1.88.0} (MOCK HARNESS TEST)" ;;
      metadata) echo '{}' ;;
      risczero)
        if test "$2" = --version; then echo 'cargo-risczero 3.0.3'; else
          mock_program "$(pwd -P)" "$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/docker/guest.bin"
          cp "$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/docker/guest.bin" "$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/docker/guest-minimal.bin"
        fi ;;
      *) exit 90 ;;
    esac ;;
  cargo-prove)
    test "$1" = prove
    case "$2" in
      --version) echo 'cargo-prove sp1 (58c4aea MOCK HARNESS TEST)' ;;
      build)
        mock_source=''
        while test "$#" -gt 0; do
          if test "$1" = --workspace-directory; then mock_source="$2"; fi
          shift
        done
        mock_program "$mock_source" "$mock_source/repro-output/sp1.elf" ;;
      vkey)
        if test "${MOCK_MODE:-pass}" = bad_id; then echo 'NO ID'; else
          printf 'Program %s has verification key: 0x%s\n' "$4" "$mock_id"
        fi ;;
      *) exit 91 ;;
    esac ;;
  rustc) echo 'rustc 1.88.0-dev (MOCK HARNESS TEST)' ;;
  r0vm)
    if test "$1" = --version; then echo 'risc0-r0vm 3.0.3'; else echo "$mock_id"; fi ;;
  rzup) echo 'MOCK HARNESS TEST toolchain 1.88' ;;
  docker)
    case "$1" in
      version|info) echo 'MOCK HARNESS TEST docker' ;;
      run) exit 0 ;;
      image)
        if test "${3:-}" = --format; then echo linux/amd64; else echo '[]'; fi ;;
      *) exit 92 ;;
    esac ;;
  *) exit 93 ;;
esac
