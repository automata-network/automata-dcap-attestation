# DCAP V2 implementation

Baseline: DCAP `41aedff`; PCCS `c65b4b1`. Source of guest build projects: staging `942d42c`.

No live deployments, router mutations, SDK publication, or replacement of legacy ELF files.

- [x] Additive strict PCCS identity parser and regression tests.
- [x] Solidity OutputV2 codec and cross-language vectors.
- [x] Dual-path V3/V4/V5 verification and FeeV2 with independent ZK defaults.
- [x] Rust identity verification and OutputV2 codec.
- [x] Isolated V2 guest source/build projects and host integration (all three backends built locally; real-proof gates remain below).
- [x] Rust/Go SDK bindings, direct calls, parsers and registry support.
- [x] Safe deployment/rollback tooling and release manifest template; local staged migration/rollback tests.
- [x] Unit/integration tests, deployed-size checks and legacy regressions (see limits below).
- [x] Same-image paired Docker builds for all three guests at frozen source `81646e5`; artifact bytes and native IDs match (see evidence below).
- [ ] Real RISC Zero/SP1 proofs against the intended supported-network universal verifiers and FeeV2; final release artifact/metadata freeze.
- [x] Commit PCCS changes and pin the new PCCS submodule commit (`f1406ef`).
- [ ] Target-chain fork rehearsal, release addresses/program IDs, publication and deployment.

Guest binaries and published addresses must not be fabricated when build/deployment prerequisites are unavailable.

## Public ATA SGX/TDX follow-up (2026-09-11)

- Extended retry: **RISC Zero real local composite receipt now passes**, with
  exact journal parity and modified-journal/wrong-image-ID/modified-seal
  rejection. Elapsed 1:03:19, maximum RSS about 3.50 GiB; saved receipt and logs
  are archived locally under `docs/evidence/dcap-v2/2026-09-11/ata-proofs`.
  **SP1 real CPU core proof also passes**, including exact journal and modified
  journal/wrong verifying key/modified proof-commitment rejection. Its successful
  release-host run took 11:55.22, maximum RSS about 7.17 GiB. An earlier 10 GiB
  virtual-limit allocation failure is retained separately; the successful
  retry used allocator/address-space tuning with a physical-memory watcher,
  not changed guest code, proof parameters or skipped checks.
  The user removed the one-hour deadline; both ran sequentially on SGX V3 only.
  Both saved artifacts were extracted into fresh directories and reverified
  in fresh processes, including all rejection checks; both exited 0.
  No TDX/V5 real proof was produced in this retry. This does not close the EVM-compatible
  proof/universal-verifier/FeeV2 or full fork gates.
- Preserved both supplied quote files unchanged, plus an explicit extracted
  TDX prefix. Original TDX is 8,000 bytes: its declared quote occupies 4,935
  bytes followed by 3,065 zeros. Strict V2 rejects the original; only the exact
  authenticated prefix is the positive fixture. No verifier normalization or
  signed-byte modification was introduced.
- Captured full authenticated collateral, offline ABI inputs and immutable
  journals at `1789139978`, evaluation 20. SGX returns `OutOfDate` and TDX
  `UpToDate`; both are Platform CA / PIID-present. Added reusable fixture
  inspection/preparation tooling with explicit extraction and no overwrites.
- Native Rust **35 tests pass**. Solidity **92 tests pass**, including 19 new
  tests through real local PCCS upserts, P-256 and FeeV2, without crypto mocks.
  Go parser/FeeV2/registry packages pass, including new ATA journal regressions.
- Canonical Docker RISC Zero/SP1/Pico programs each execute both samples and
  match complete native/Solidity journals (833/873 bytes): **6 positive guest
  executions**. RISC Zero/SP1 additionally pass **32 negative guest checks**
  across eight input mutations. Pico remains positive execution/local-only.
- Initial bounded run: added explicit-local real composite/core proof diagnostics.
  Both compiled; five development-mode/VK/shape guards passed. Each SGX attempt timed
  out after 600 seconds (exit 124) on this ARM64 worker, with bounded memory
  and two Rayon threads. No completed receipt/proof was saved in that run and
  its logs do not establish proof-cryptography or proof-tampering checks.
  The extended retry above supersedes this local-proof status. EVM-compatible
  compression and universal-verifier/FeeV2 proof acceptance remain open.
- Retained logs, exact inputs and public PCS responses in optional local archives;
  Git keeps the test sources/fixtures, text hashes, result summary and archive-free
  repeat procedure. The new ATA archives are ignored, not deleted. See the
  [public-quote validation report](dcap-v2-public-quotes-validation.md).
  Guest source/locks/artifacts/native IDs, old user evidence and production
  configuration are unchanged. Full fork acceptance remains deferred,
  including `CrlV2AeneidForkTest`; no fork or live deployment was started.

## Evidence retention and Pico release scope (2026-09-11)

- Archived the new execution evidence unchanged under
  [docs/evidence/dcap-v2/2026-09-11](evidence/dcap-v2/2026-09-11/README.md), with a
  SHA-256 manifest and provenance/scope notes. The original returned build
  archives and session logs in the repository root were not moved or modified.
- User confirmed Pico is **local-only**, with no network deployment or new
  program/default/route registrations. Preserve the current network/backend
  matrix; production acceptance covers RISC Zero/SP1 only where already
  supported. Pico local source/SDK/build/execution support remains intact.
- Pico local real-proof verification remains a separate, non-production TODO;
  it has not passed and no new setup was generated. Recovering parameters for
  an assumed deployed Pico verifier is no longer a release prerequisite. A
  local proof test must use a matching local circuit/key/verifier set.
- Updated the rollout, fork acceptance checklist and example release manifest
  to reflect that scope. No fork test, live configuration change or deployment
  was performed, and no commit was created automatically.

## Returned Mac evidence and guest regression (2026-09-11)

- Independently checked the returned RISC Zero/SP1 evidence archives and session
  logs: pinned image/platform, source archive, harness hashes, locked guest
  dependencies, actual A/B program bytes and native IDs all agree. Logs show
  fresh guest compilation in both runs. Source is frozen at
  `81646e5754a8124d4a70a483882f11b515c98c7b`, not the uncommitted working tree.
- RISC Zero/SP1 both pass same-image Docker reproducibility on the user's Mac.
  Together with the earlier Pico paired builds, this closes the build check
  for all three backends **at that source/build configuration**. Matching an
  earlier host-native artifact remains unnecessary.
- Executed each returned A program against authentic V3/V4/V5 and each B program
  against V5 using the local pinned SDKs: **8 successful executions and 16
  rejection checks passed**. All journals match native verification and frozen
  expectations byte-for-byte (833 / 1,225 / 937 bytes), decode as OutputV2 2.1,
  and preserve PPID/PIID/presence semantics. Independently computed Linux SDK
  native IDs agree with the Mac CLI results.
- Recorded complete artifact/native-ID values, archive hashes, execution
  matrix and repeatable input references in the
  [Docker evidence record](dcap-v2-container-rebuild.md#returned-mac-build-evidence-2026-09-11).
  Original user archives, legacy binaries, host candidates and registrations
  are unchanged. This follow-up changes documentation only in the repository.
- Real RISC Zero/SP1 proofs and intended universal-verifier/FeeV2 integration remain open;
  execution is not proof verification. The final manifest must bind the tested
  source, image/platform, locks, harness and native IDs. Rebuild/revalidate if
  guest source, dependencies or the build recipe change. The user-deferred
  [full fork acceptance](dcap-v2-fork-validation.md) has not started.

## Apple Silicon official-image handoff (2026-09-11)

- User-reported Mac preflight passed for both digest-pinned AMD64 official
  images on macOS 26.6.2 / Docker Desktop 4.90.0 / engine 29.7.2, with Apple
  Virtualization framework and Rosetta enabled. RISC Zero reports Rust/Cargo
  1.88-dev; SP1 reports Rust 1.88-dev and Cargo 1.90.0. Keep the image tools as-is.
- The Mac has 24 GiB RAM. Docker reported about 7.75 GiB at preflight and in the
  successful returned builds; 12 GiB was a recommendation, not a tested minimum.
- Added a frozen-source handoff, macOS hash/path compatibility, host metadata
  Cargo 1.88 pin, normalized native-ID comparisons, and success/failure evidence
  archives. No guest source, production artifact or deployment setting changed.
- Five existing command guards and seven new **mock orchestration/portability**
  cases pass. These test script behavior only, not compilers or cryptography.
- Official-image paired builds and returned-program execution have since
  passed as recorded above; real-proof verification remains pending.

## Release build criterion correction (2026-09-11)

- Per the team's existing process, reproducibility means **two independent
  clean builds in the same digest/platform-pinned Docker image**, not equality
  between a generic container and an arbitrary host build. The earlier mismatch
  is retained as a diagnostic, not a failed Docker-only release gate. No guest
  path-normalization change is required solely to match the old host hashes.
- Resolved the official RISC Zero `r0.1.88.0` and SP1 `v5.2.2` image digests.
  Both images target AMD64. The SP1 image was pulled, but its no-op preflight
  fails with `exec format error` on this ARM64 worker. An AMD64 Docker worker
  or separately configured emulation is needed; no privileged setup was run.
- Added paired-build tooling using the official SDK Docker paths, plus a Pico
  image with the fixed nightly installed before either run. No host guest
  compiler/target cache is mounted. Official-image execution remains blocked
  at preflight here.
- Pico: **two clean containers produced byte-identical ELFs**, using the same
  frozen ARM64 image and source `81646e5`. Compiler and lockfile records match.
  The canonical Docker ELF SHA-256 is
  `8d0dc7c137e1a2b3f336acc05ac82125833f385201cd11a5bfbf1e02128b31b4`.
  Both runs' independently computed SDK native ID is
  `0x000e95d6b7f85b7a9302081b512ab1dff0fad9759b89411d083760c7d554efd6`;
  both Google V5 executions match the 937-byte native journal (179,886,646 cycles
  each). Both build containers are stopped and retained. Pico's current runner
  covers successful execution only, not the RISC Zero/SP1 negative-test matrix.
- Five command-shape/argument-guard smoke checks and shell syntax checks pass.
  These do not establish RISC Zero/SP1 build or real-proof success.
- See [canonical Docker build procedure](dcap-v2-container-rebuild.md). Guest
  regressions, real proofs, frozen release metadata and the deferred fork
  acceptance remain required. No registrations or deployments occurred.

## Frozen fixtures, V5 Solidity parity and container follow-up (2026-09-11)

- Persisted the exact V3/V4/V5 ABI inputs from the earlier backend execution
  checks as public JSON fixtures, with individual quote/collateral components,
  fixed timestamps, provenance, SHA-256 values and immutable expected journals.
  Added an offline input exporter and explicit, non-overwriting capture command.
  Tests reconstruct the ABI from components; they never regenerate expectations.
- Added authentic Google V5 success through real PCCS DAOs, signature/chain
  verification and FeeV2. The full journal matches the native/three-guest 937-byte
  output. This uses explicit evaluation number 20; automatic evaluation-number
  selection is a separate fork acceptance item. Changed-body and pre-validity
  rejection cases pass. No cryptographic mocks or online collateral fetches.
- Solidity: **73 tests passed** across 18 suites, excluding the explicitly
  deferred `CrlV2AeneidForkTest`. Rust: **33 tests passed** (28 unit, 3 existing
  OutputV2 tests, 2 new fixture tests covering all three versions). The initial
  Rust incremental build hit a missing-object filesystem error; retrying with
  `CARGO_INCREMENTAL=0` passed. Existing unrelated warnings remain.
- All three offline exported ABI hashes equal those recorded in the earlier
  SP1/RISC Zero/Pico sections. The exporter also rejects existing destinations.
- Completed a pinned Rust ARM64 container rebuild of committed source `81646e5`,
  without host build caches. All three compile with unchanged guest lockfiles,
  but all three artifact hashes and native IDs differ from the host baseline.
  All three container-built programs pass Google V5 journal parity; RISC Zero/SP1
  also pass both rejection cases. RISC Zero/Pico contain differing absolute
  Cargo paths; the SP1 host/container difference was not diagnosed. Portable
  reproducibility was not established by this cross-environment comparison;
  it is **not a failure of the agreed Docker-only criterion**. See the [container runbook](dcap-v2-container-rebuild.md)
  for exact inputs, limitations and the follow-up gate. Original host candidates
  are unchanged; no new native IDs were registered.
- Checked the Pico public download candidate's 520-byte `vm_vk`: none of its 20
  relevant coordinate constants match the repository's existing Groth16 verifier.
  It is not a compatible substitute for that verifier. Recovering the original
  bundle is necessary only if that verifier is the chosen local test target;
  it is not an online release gate under the confirmed Pico local-only scope.
  `constraints.json` can be regenerated by the pinned SDK, but must describe
  the matching circuit. No new setup was performed.
- Recorded the mandatory [fork acceptance TODO](dcap-v2-fork-validation.md):
  deployment, live configuration inventory, migration/rollback, raw and real-ZK
  verification, Rust/Go SDK coverage and detailed gas/off-chain cost reporting.
  This phase has **not started**, per the user's sequencing request.

See [fixture provenance and repeatable commands](../evm/forge-test/assets/v2/fixtures/README.md)
and [Pico local validation](../rust-crates/libraries/zkvm/methods/pico/README.md#local-validation-status-not-a-production-release-gate).

## RISC Zero toolchain follow-up (2026-09-11)

- Confirmed the user's ARM64 RISC Zero compiler, `cargo-risczero` and `r0vm`
  installation. SDK/build driver/CLI/runtime stay at 3.0.3; no SDK upgrade,
  remote proving request, legacy artifact replacement or deployment occurred.
- Generated the guest lockfile using Rust 1.88-compatible resolution, with
  `ruint` 1.17.0 matching the host and SP1. Existing crypto-patch tags and the
  host/driver lockfiles are unchanged.
- The build driver selects the separate Cargo 1.88.0 on its child PATH because
  upstream `risc0-build` strips `RUSTUP_TOOLCHAIN`; the compiler still comes from
  rzup. It forces `RISC0_BUILD_LOCKED=1`, making the actual guest build locked.
  The default system toolchain and the other backends are unchanged.
- Two builds in separate target directories on this machine produced identical
  program binaries (SHA-256 and byte comparison). This is not yet independent
  machine/container reproducibility.
- The local candidate path's `.elf` suffix is historical: RISC Zero 3.x
  `embed_methods` produces a combined user/kernel program binary. Its native
  image ID was computed by the installed `r0vm` 3.0.3, not inferred from SHA-256.

```text
guest compiler: rustc 1.88.0-dev (de85b1d3d 2025-06-26), LLVM 20.1.5
rzup rust component: 1.88.0+de85b1d3d7f
guest Cargo: 1.88.0 (873a06493 2025-05-10)
guest Cargo.lock SHA-256: b1effad0065ea61600220be04a4610f260b8089aeec996bc3a8ffa5a0e80f190
driver Cargo.lock SHA-256: 85e63d2be4fa98637c3fa77b1da7c998005288e46d04db9d95f3dc65b0fefcd3
program binary SHA-256: d82d74162f391601c2898321f714f054d2dd1740ca158a6cce0036c9f877a911
native image ID: 0x3a614cc52976def28c0af46ce5faa00632673474df582f6915c680ea5c769206
```

These are local candidates, not approved release registrations. The SDK's
`compute_image_id` independently agrees with the `r0vm` CLI result above.

- V3/V4/V5 all executed successfully in the real local `r0vm` subprocess,
  halted with status zero, and produced journals byte-identical to native V2
  verification. SDK decoding confirms OutputV2 2.1 and PIID present in all three.
- All six changed-body/pre-validity inputs were rejected by both native and
  guest verification. The runner requires a DCAP verification panic, not an
  arbitrary VM fault, IPC failure or cycle-limit error. A separate host guard
  check confirmed `RISC0_DEV_MODE=1` is refused.
- Re-ran the locked/offline DCAP regressions: 28 unit plus 3 OutputV2 integration
  tests passed. Formatting and whitespace checks passed. Existing unused-import
  and dependency future-compatibility warnings were not changed.
- The host example was linked with the Rust toolchain's bundled LLD (two
  threads). Running `r0vm` required local subprocess/loopback IPC permission;
  no Bonsai request, remote prover, fake receipt or actual proof was used.

| Quote fixture | Timestamp | RISC Zero user cycles | Journal bytes | Exact parity | Rejection cases |
| --- | ---: | ---: | ---: | --- | --- |
| Repository V3 | 1755236700 | 14,340,455 | 833 | PASS | 2/2 PASS |
| Repository V4 | 1749095100 | 13,784,512 | 1,225 | PASS | 2/2 PASS |
| Public Google V5 / TD 1.5 | 1789052566 | 14,309,098 | 937 | PASS | 2/2 PASS |

Inputs and SHA-256 values are identical to those recorded in the SP1 section
below. These are fixed verification timestamps, not a claim of current
collateral freshness. User cycles exclude continuation overhead and proof
padding; do not equate cycle counts across different VMs. Real receipts,
universal-verifier compatibility and independent-machine reproducibility
remain separate release prerequisites.

See [RISC Zero build and execution instructions](../rust-crates/libraries/zkvm/methods/risc0/README.md).

## SP1 toolchain follow-up (2026-09-11)

- The official Linux ARM64 `succinct-1.88.0` compiler and RISC-V standard
  library are installed. The distribution omits Cargo; `cargo +succinct` falls
  back to the system Cargo and is not a sufficient build-readiness check.
- Actual compilation found two compatibility blockers: guest lockfile
  `ruint 1.20.0` requires Rust 1.90, and system Cargo 1.97.1 passes
  `--remap-path-scope`, unsupported by the Succinct Rust 1.88 compiler.
- The guest now declares Rust 1.88 and locks `ruint` to 1.17.0, matching the host
  workspace. A separate Cargo 1.88.0 was installed, without changing the default
  toolchain. The build driver validates and selects it for child processes;
  `sp1-build` still explicitly uses the Succinct compiler for the guest.
- The V5 verifying-key map was downloaded from the official SP1 asset URL and
  checked against upstream SHA-256. No dummy VK map, VK-verification bypass,
  skipped guest build, mock proof or remote paid proving request is used.
- The V2 guest built successfully using Cargo 1.88.0 and Succinct Rust
  1.88.0-dev. A second build via the official 5.2.2 CLI, in an independent empty
  target directory on the same machine, produced a byte-identical ELF.
- Official CLI native program ID was computed with the default circuit shapes
  and VK checks enabled. These are local candidates, not release registrations:

```text
guest Cargo: 1.88.0 (873a06493 2025-05-10)
guest compiler: rustc 1.88.0-dev; LLVM 20.1.5; succinct-1.88.0
guest Cargo.lock SHA-256: d7aadb020fc6f848e600eb423274c3701a9aa0fd24865aa087e5944258f7e20f
driver Cargo.lock SHA-256: ef4c9b99bb28697f02adb4fc1089c858403e648d89541ffd9a9ab586fa536bb6
SP1 ELF SHA-256: 8d69f868a1d8dff1c5d3b3d87d3c1921587e802640f19a2ebb80189f6db0a830
SP1 native program ID: 0x00bd7025b04b40b22c8aeca3bafd53ef59a05161fceb9780fac2f94c0d0606c3
```

- Added a local CPU execution example for exact journal parity and rejection
  checks (changed signed body and pre-validity timestamp). All three signed
  Quote V3/V4/V5 fixtures passed exact native/SP1 journal parity and SDK decoding,
  with OutputV2 2.1 and PIID present. All six invalid inputs were rejected by
  native verification and by a guest validation panic (exit code 1); neither
  cycle-limit exhaustion nor arbitrary execution errors count as rejection.
- Host execution reports circuit version `v5.0.0` and the same native program ID
  as the official CLI. The first GNU host link was killed under memory pressure;
  relinking only the example with Rust's bundled LLD (two threads) succeeded.
  This host-only adjustment does not change the guest ELF or circuit settings.
- Real proof verification and independent-machine/container reproducibility
  remain pending; local execution is not a real-proof release gate pass.
- Re-ran the locked, offline DCAP core regressions: 28 unit and 3 OutputV2
  integration tests passed, including the signed V3/V4 output vectors and
  production-policy rejection of the migration-enabled V5 fixture.
- RISC Zero installation is being handled separately by the user; no changes
  to that toolchain or its source checkout were made in this follow-up.

Execution evidence (fixed verification timestamps, not a claim of current collateral freshness):

| Quote fixture | Timestamp | SP1 cycles | Journal bytes | Exact parity | Rejection cases |
| --- | ---: | ---: | ---: | --- | --- |
| Repository V3 | 1755236700 | 14,482,696 | 833 | PASS | 2/2 PASS |
| Repository V4 | 1749095100 | 13,944,647 | 1,225 | PASS | 2/2 PASS |
| Public Google V5 / TD 1.5 | 1789052566 | 14,450,166 | 937 | PASS | 2/2 PASS |

V3/V4 ABI inputs were reconstructed from the same signed quote/collateral fixtures
used by `dcap-rs/tests/output_v2.rs`; their native journals match the checked-in
`verified-v3.hex` and `verified-v4.hex` vectors. The Google V5 input is the same
one used for the Pico execution below. The encoded inputs are local diagnostic
files at that checkpoint; they are now checked in as described above. ABI input SHA-256 values:

```text
V3: a541671d3a37b9d6f1877edfc2c600217cf58fee8488d0a2af1ef3d8fd1aad5e
V4: 3e0eb6ab34f89434a9442aa06728b10fd82a97b7fb6e4ca725dfe666bab520ea
V5: 99c9630ffd878ab2800b5d72ca90d07b077ef360eec83efa116815e2200419a9
```

See [SP1 build and execution instructions](../rust-crates/libraries/zkvm/methods/sp1/README.md).

## Pico build compatibility follow-up (2026-09-10)

- Replaced the Pico 1.1.6 CLI build wrapper with a std-only driver using installed
  nightly-2025-08-04 + rust-src. SDK/VM 1.1.6, KoalaBear, target, linker settings,
  atomic lowering and the universal-verifier family remain unchanged.
- Generated the Pico guest lockfile. The ECDSA patch's unversioned Git dependency
  initially resolved to incompatible pico-patch-libs 2.1.2; pinned it to the same
  `5aa0bd9ca60c366618856681d8a7ad356753a979` revision as SDK/VM 1.1.6. The inner
  build is `--locked`, not merely the outer build driver.
- Pico guest compiled successfully. A second build from an empty target
  directory on the same machine produced an identical ELF. This is not yet an
  independent-machine/container reproducibility result.
- Build-driver regressions: 3 passed (pinned/locked command, codegen environment,
  ELF header rejection). Pico host regressions: 5 passed with the pinned nightly.
- Executed the authentic public [Google Quote V5 / TD 1.5 sample](https://github.com/google/go-tdx-guest/blob/48f3644ca143b4800def5f89dca819294606bf4e/testing/testdata/quote_sample_v5.dat)
  with matching Intel collateral and verification timestamp `1789052566`:
  **179,886,646 cycles; 937 journal bytes; exact native/Pico V2 parity passed**.
  The sample meets production policy, has zero MR_SERVICE_TD, and verifies with
  UpToDate status and PIID present. Inputs were local diagnostic data at that
  checkpoint; they are now checked-in fixtures and Solidity parity has passed
  as recorded above. This run used the real guest, not DEV_MODE or a mock verifier.
- No real V2 proof or on-chain registration was produced. The default Pico
  artifacts directory is absent. A local real-proof test still needs a matching
  circuit/key/verifier set; it is separate from the production release. A fresh
  local test setup cannot be treated as compatible with the old verifier. See
  the confirmed local-only scope and conditional parameter guidance above.

Local **candidate**, not an approved release/allowlist entry:

```text
guest rustc: 1.91.0-nightly (f34ba774c 2025-08-03)
guest Cargo.lock SHA-256: 37e02e2bff69a84992af9811c9a095ef2a522de227d7b8f1d98c6629537a907f
Pico ELF SHA-256: e00f14f0cab5066be61c0b5f1d0a7b80dd7a4c7262d2bccdf5cc0302e561ab42
Pico native program ID: 0x00aeb9334e33f5cdce39eaa13aef0cbe1d387384669756045df3c1221df8fe6a
Google V5 quote SHA-256: cf77a6e91e48291d5d338c5f3b5d0674225a4d13e7d83ff5e537a4914bf22e1d
V2 ABI input SHA-256: 99c9630ffd878ab2800b5d72ca90d07b077ef360eec83efa116815e2200419a9
```

See [build, lockfile and execution instructions](../rust-crates/libraries/zkvm/methods/pico/README.md).

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
- R1 remains a release prerequisite. At the security-fix checkpoint no guest ELF,
  native program ID or real V2 proof had been produced; subsequent Pico build
  evidence is recorded above. No registration/publication/deployment was performed.

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

- All three toolchains, guest/build-driver lockfiles and local V2 program binaries/native IDs are now available. SP1 and RISC Zero use separate Cargo 1.88 for guest builds. Pico does not need cargo-pico; see local build evidence above.
- Paired fixed-image builds for all three backends pass at source `81646e5`. Final release metadata still needs freezing; repeat checks if guest source, dependencies or recipe change. Real RISC Zero/SP1 proofs against supported-network universal verifiers and FeeV2 remain outstanding. Mock/execution-only tests do not establish proof correctness or verifier compatibility.
- Pico remains local-only. Local real-proof testing is still open but does not require a supported-network deployment and does not block production release; do not add Pico network routes/defaults/IDs.
- The public Google V5 sample now passes native/three-guest and Solidity FeeV2 journal parity. Complete signed inputs, collateral, fixed timestamps and expected outputs are checked in and rebuild offline.
- `CrlV2AeneidForkTest` requires an external RPC and was excluded. The local rollout tests are not target-chain fork simulations or broadcasts.
- PCCS changes are committed in `evm/lib/automata-on-chain-pccs`, pinned at `f1406ef`; the sibling repository was not edited.
- Final source/artifact freeze, real proof verification for production-enabled RISC Zero/SP1 backends, live configuration inventory and fork rehearsal must pass before release. Preserve the existing network support matrix. See [rollout](dcap-v2-rollout.md) and [manifest template](dcap-v2-release-manifest.example.json).
