# V2 guests

Selectively ported from staging `942d42c8a8543a28ed737db515fb8e8c246aca61`.
The verifier core remains the current main implementation. Each backend has a
strict binary calling `verify_guest_input_v2` and a separate minimal binary
calling `verify_guest_input_v2_minimal`. Both commit canonical compact output.

Current semantics: mode is compile-time fixed, never guest input. The new
AttestationV2 registry binds each ID immutably to its mode and requires exact
call-mode matching; the default must be strict. The compact journal commits
`keccak256(quoteBody)` instead of the body. Full quote hash remains Keccak;
RISC Zero's journal digest remains SHA-256. Old inline-body artifacts/IDs/proofs
must not be reused. Output schema remains unreleased 2.1.
See [mode semantics and release gates](../../../../docs/dcap-v2-min-check.md).

These are standalone build workspaces. Ordinary host builds do not build guests.
Build drivers write mode-specific `BACKEND-strict.elf` and `BACKEND-minimal.elf`
under `zkvm/artifacts/v2.0`; old embedded v1.0/v1.1 ELFs are untouched.
Pico retains main's v1.1.6 SDK/universal-verifier family, not staging's v1.2.2.

Before release:

1. Install the pinned backend toolchains; resolve and commit each guest and build-driver Cargo.lock.
2. Run `cargo build --release --locked --manifest-path <backend>/Cargo.toml`.
3. Record source/submodule revisions, Cargo.lock hashes, toolchains, ELF SHA-256, native program identifiers and proof selectors.
4. Repeat the build in a clean environment and compare hashes.
5. Produce real proofs and verify them against the reused universal verifiers.

An ELF digest is not a program identifier. No placeholder ELF or program ID is registered.
Host proving may load an explicitly selected artifact; consumers must check its native
program identifier against the release manifest and the independent V2 allowlist.

CLI: select deployment version v2.0 and set DCAP_V2_ELF to the audited artifact for the
selected backend. Program-ID commands also honor this selection. V2 never falls back
to an old embedded ELF. For SP1, use a target directory literally named target, e.g.
--target-dir ../../../../target; its upstream build script rejects cargo-target paths.

Pico uses an in-repository build driver with nightly-2025-08-04 and `rust-src`;
`cargo-pico` is not required. Its guest lockfile also pins the ECDSA patch's
otherwise floating Pico dependency to v1.1.6. See [Pico build instructions](pico/README.md).

SP1 is pinned to exact 6.8.0, with the v6 64-bit guest target. Host SDK/examples
type-check with updated dependencies and async APIs. An isolated official v6
toolchain builds both modes and executes the frozen fixtures successfully,
without replacing the global v5 toolchain. The v6 Docker recipe is digest-pinned;
fresh paired builds are pending. Do not use the historical v5 Docker recipe.

RISC Zero uses the installed rzup Rust 1.88 compiler, separate Cargo 1.88 and
SDK/runtime 3.0.3. The driver also locks the inner guest build. Its `.elf` artifact
is a combined user/kernel program binary; see [RISC Zero instructions](risc0/README.md).

Build/execution status for this compact revision is in
[current status](../../../../docs/dcap-v2-revision-progress.md). Historical
inline-body acceptance does not cover it. Docker drivers/return validation now
record the selected mode and pin SP1 v6; both modes require fresh paired builds.
Fresh proofs, matching verifier routes and fork acceptance remain gates.
