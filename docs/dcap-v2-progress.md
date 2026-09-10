# DCAP V2 implementation

Baseline: DCAP `41aedff`; PCCS `c65b4b1`. Source of guest build projects: staging `942d42c`.

No live deployments, router mutations, SDK publication, or replacement of legacy ELF files.

- [x] Additive strict PCCS identity parser and regression tests.
- [x] Solidity OutputV2 codec and cross-language vectors.
- [x] Dual-path V3/V4/V5 verification and FeeV2 with independent ZK defaults.
- [x] Rust identity verification and OutputV2 codec.
- [x] Isolated V2 guest source/build projects and host integration (guest binaries not built).
- [x] Rust/Go SDK bindings, direct calls, parsers and registry support.
- [x] Safe deployment/rollback tooling and release manifest template; local staged migration/rollback tests.
- [x] Unit/integration tests, deployed-size checks and legacy regressions (see limits below).
- [ ] Reproducible guest builds and real proofs against reused universal verifiers.
- [ ] Commit PCCS changes and pin the new PCCS submodule commit.
- [ ] Target-chain fork rehearsal, release addresses/program IDs, publication and deployment.

Guest binaries and published addresses must not be fabricated when build/deployment prerequisites are unavailable.

## Security-review follow-up (2026-09-10)

- V2-only E4/E5/E6 corrections and Pico host R5 correction implemented; legacy EVM
  selectors and Solana are outside the maintenance scope.
- Go SDK G1–G4 corrected across quote parsing, Bonsai HTTP handling, shared
  Bonsai/SP1 binary decoding and collateral serialization. Some Go helper APIs now
  return errors; see [migration and verification details](dcap-v2-security-fixes.md).
- Local Solidity coverage now passes 70 tests; Pico feature tests pass 5 tests,
  including three new regressions. Go owning-package regressions, race checks,
  four focused fuzz runs, SDK build and static checks pass. One independent
  read-only candidate review found no concrete surviving bypass or regression.
- Updated runtime sizes: V3 19,764; V4 23,129; V5 23,972; FeeV2 22,306 bytes.
  V5 remains below EIP-170, with 604 bytes of margin.
- R1 remains a release prerequisite. No guest ELF, native program ID or real V2
  proof has been produced, and no registration/publication/deployment was performed.

## Verification evidence (2026-09-09)

- Solidity: 58 tests passed across 15 suites, including strict DER mutations, canonical codec/fuzz tests, version-family isolation, production quote policy, TDX status/relaunch, legacy regression and local rollout/rollback.
- Real signed Quote V3/V4 fixtures: Rust verification produces the checked-in vectors, and Solidity V2 verification returns exactly the same bytes at the same verification timestamp/collateral.
- Real signed Quote V5 fixture: legacy on-chain verification remains accepted; both V2 paths reject its non-zero migration-service measurement. A successful authenticated V5 V2 fixture is still a release gate. Synthetic TD 1.5 codec/status tests are not a substitute.
- Rust: 55 tests passed (dcap-rs 28 unit + 3 integration; network registry 14; utils 10). Full Rust host workspace check passed using `--target-dir target`.
- Go: FeeV2 direct-call/event bindings, OutputV2 parser and registry package tests passed.
- Five new deployment artifacts compile below the 24,576-byte EIP-170 runtime limit with the repository's pinned solc 0.8.27, via-IR and optimizer settings.
- Runtime sizes (bytes): Helper 13,898; V3 19,459; V4 22,620; V5 23,605; FeeV2 22,306. V5 has the smallest remaining margin: 971 bytes.
- Frozen `deployment/v1.1`: 56 JSON files; `current` and default SDK version still refer to v1.1. No V2 addresses are published.

Commands (from `evm`, `rust-crates`, and repository root respectively):

```sh
forge test --no-match-contract CrlV2AeneidForkTest -vv
forge build --skip test --sizes
cargo test -p dcap-rs --lib --test output_v2 -p automata-dcap-network-registry -p automata-dcap-utils --offline
cargo check --workspace --offline --target-dir target
go test ./go-sdk/packages/godcap/feev2 ./go-sdk/packages/godcap/parser ./go-sdk/packages/godcap/registry
```

## Outstanding build/release gates

- Actual guest build attempts stopped at missing RISC Zero Rust, Succinct and cargo-pico toolchains. RISC Zero/Pico guest lockfile generation additionally needs crypto-patch Git dependencies absent from the offline cache. Three build-driver lockfiles and the SP1 guest lockfile are present; the other two guest lockfiles are not.
- No V2 ELF, native program ID, real ZK proof or reproducibility result has been produced. Tests using mock universal verifiers establish routing/journal behavior only, not proof correctness or universal-verifier compatibility.
- `CrlV2AeneidForkTest` requires an external RPC and was excluded. The local rollout tests are not target-chain fork simulations or broadcasts.
- PCCS changes are in `evm/lib/automata-on-chain-pccs`; the sibling repository was not edited. Both repositories still need reviewed commits, including the new submodule pin.
- Toolchain installation/pinning, two clean guest builds per backend, successful authenticated V5 parity, real proof verification, live configuration inventory and fork rehearsal must pass before release. See [rollout](dcap-v2-rollout.md) and [manifest template](dcap-v2-release-manifest.example.json).
