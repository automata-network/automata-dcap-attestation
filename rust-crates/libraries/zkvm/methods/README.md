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

Current validation status: host/build-driver compilation was attempted locally, but
RISC Zero Rust, Succinct and cargo-pico toolchains are not installed. RISC Zero and
Pico guest lockfile resolution also requires uncached crypto-patch Git dependencies.
The three build-driver lockfiles and SP1 program lockfile exist; the remaining
guest lockfiles, all V2 ELFs, native IDs and real proof checks are still outstanding.
Do not treat these source projects as reproducibly built release artifacts.
