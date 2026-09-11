# V2 guests

Selectively ported from staging `942d42c8a8543a28ed737db515fb8e8c246aca61`.
The verifier core remains the current main implementation. All guests call
`dcap_rs::v2::verify_guest_input_v2` and commit its exact bytes.

These are standalone build workspaces. Ordinary host builds do not build guests.
Build drivers write only to `zkvm/artifacts/v2.0`; old embedded v1.0/v1.1 ELFs are untouched.
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

SP1 uses a separate Cargo 1.88.0 with the official Succinct Rust 1.88 compiler.
The driver does not rely on `cargo +succinct` falling back to a newer system
Cargo. See [SP1 build instructions](sp1/README.md).

RISC Zero uses the installed rzup Rust 1.88 compiler, separate Cargo 1.88 and
SDK/runtime 3.0.3. The driver also locks the inner guest build. Its `.elf` artifact
is a combined user/kernel program binary; see [RISC Zero instructions](risc0/README.md).

Current validation status: all three V2 guests have compiled locally, with all
guest and build-driver lockfiles present. All backends still require independent
reproducibility and real proof checks before release. Local execution checks are
not proof validation; see [current evidence](../../../../docs/dcap-v2-progress.md).
