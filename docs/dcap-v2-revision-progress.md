# Unreleased V2 compact journal / SP1 v6 revision

Status: implementation in progress. No deployment or new-proof acceptance claim.

Confirmed requirements:
- Rename the entrypoint to AutomataDcapAttestationV2; expose no legacy verification
  or legacy program-registry entrypoints. Existing legacy contracts remain unchanged.
- Register immutable strict/minimal program modes separately from setting the
  strict-only default. All three backends have two compile-time-fixed programs.
- Preserve unreleased wire version 2.1, replace quoteBody with keccak256(body),
  retain fullQuoteHash, and return authenticated body separately for raw calls.
- AttestationSubmittedV2 additionally records programIdentifier and minCheck.
- Pin SP1 6.8.0 and migrate guest, host, proving, verifier routes and Docker builds.
- Add resumable isolated deployment orchestration and versioned registry publication;
  never mutate existing routes/collateral or promote current without explicit authority.

Compact wire layout (big endian; advisory payload is canonical ABI string[]):

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 2 | formatMajorVersion = 2 |
| 2 | 2 | formatMinorVersion = 1 |
| 4 | 1 | legacy rejection marker = 6 |
| 5 | 2 | quoteVersion |
| 7 | 2 | quoteBodyType |
| 9 | 1 | tcbStatus |
| 10 | 6 | fmspc |
| 16 | 16 | ppid |
| 32 | 16 | piid |
| 48 | 1 | piidPresent |
| 49 | 2 | advisoryOffset: 0 if empty, otherwise 317 |
| 51 | 2 | advisoryLength |
| 53 | 8 | timestamp |
| 61 | 192 | six collateral hashes in existing order |
| 253 | 32 | fullQuoteHash (Keccak-256) |
| 285 | 32 | quoteBodyHash (Keccak-256 of exact report body) |
| 317 | variable | advisoryIDs, omitted if empty |

Old test-only 2.1 journals, program IDs and proofs are incompatible. Never
register their minimal-baseline IDs as new strict programs. Old deployment
records are historical; renaming a registry key must not relabel old bytecode
as a compatible new deployment.

Acceptance work remaining is tracked by the implementation results in this file.
Historical proof/collateral mismatch on Hoodi requires fresh input preflight
before generating new proofs; it must not be bypassed by editing a journal.

## Implementation checkpoint (2026-09-18; uncommitted working tree)

Implemented locally:

- Independent `AutomataDcapAttestationV2` admin/entrypoint, no legacy verification
  or program-registry selectors; separate verifier, registration and strict-default
  operations. Removed IDs retain their original mode and cannot be reinterpreted.
- Compact Solidity/Rust/Go codecs, raw triple returns, body-hash binding helpers,
  event metadata and cross-language frozen vectors. Signed fixture quote,
  collateral and ABI input bytes are unchanged; only expected journals changed.
- Rust typed raw return and V2 bindings; Go client renamed `attestationv2`.
  V2 registry requires the new entrypoint key, with no fallback to the old test FeeV2.
- Go `sp1.NewV6Client` explicitly selects circuit v6.1.0, preserving legacy
  defaults. Its Groth16 network decoder handles five public inputs and emits
  the SDK's 356-byte EVM encoding, with exit/root/journal/program binding checks.
  These are transport/metadata checks, not local cryptographic proof verification.
- Dual guest entrypoints on all three backends; RISC Zero/Pico local builds
  completed, output filenames include strict/minimal. SP1 guest/build/host are
  pinned to 6.8.0 with updated locks and v6 crypto patches. Its async host SDK and
  all examples type-check, including an explicit local CPU multi-format proof
  runner. ELF32/legacy checkpoint inputs are rejected. An isolated official v6
  ELF64 toolchain builds both modes without replacing the global v5 toolchain.
  Real proving with reviewed Docker artifacts remains pending.
- Local guest execute runners (`risc0/sp1/pico_v2_execute`) accept
  `--expect-reject` for mode-divergent policy fixtures: native rejection in the
  selected mode plus a genuine guest rejection (R0 validation panic, SP1 exit 1
  with marker, Pico non-zero halt) is required. `verify-current-guests.sh` now
  runs the Alibaba V5 policy cell per backend/mode.
- Isolated deployment coordinator, checkpointed broadcasts, signer/resolver
  inventory, finalized readback, source verification and versioned publication.
  Helper/publisher unit tests pass; full coordinator end-to-end rehearsal is pending.
- Independent SP1 v6.1.0 Groth16 verifier deployment option (SDK 6.8.0), pinned
  upstream submodule source. Existing gateway/verifier routes remain unchanged.
  Foundry isolates its upstream Solidity 0.8.20 unit from DCAP Solidity 0.8.27.

Verified:

- 2026-09-21 (this Mac, foundry 1.6.0-nightly): full Foundry suite **121 passed,
  0 failed, 2 skipped** (Sepolia fork requires `DCAP_FORK_RPC`, Story regression
  requires `STORY_RPC_URL`), including the new 4-test `AlibabaV5PolicyV2Test`.
  Runtime: 19,819 bytes (one-byte nightly/compiler delta vs the 19,818 record;
  0.8.27 compilation restrictions unchanged). Earlier: **117 passed, 0 failed,
  2 skipped**. Legacy proof tests in that total are not new compact-guest proof
  acceptance.
- 2026-09-21 production-policy fixture: signed Alibaba V5 quote (non-zero
  MR_SERVICE_TD) with collateral/timestamp donated unchanged from the v5.json
  snapshot (same FMSPC). Native strict rejects with `TDX migration service TD
  measurement is not zero`; native minimal accepts with a frozen 1,245-byte
  journal; eight collateral/signature mutations reject in both modes
  (`alibaba_v5_strict_rejects_minimal_accepts_with_frozen_journal`). The quote,
  its PCK chain and the signed collateral JSON were not modified.
- 2026-09-21 (ARM64 Linux VM, Go 1.26.2): compact client/parser/registry and
  SP1 legacy/v6 transport tests rerun and pass (`-count=1`); `go test ./... -run
  '^$'` compiles every package offline. This replaces the earlier "Go toolchain
  unavailable" entry.
- 2026-09-21 zkVM guest policy matrix for the Alibaba V5 fixture (explicit
  exported input, host runners rebuilt from current source): all three backends
  agree with native — strict guest rejects with the migration-service-TD
  validation marker, minimal guest accepts with frozen 1,245-byte journal parity.
  RISC Zero 3.0.3: strict guest panic + native reject; minimal 14,397,437 user
  cycles, parity PASS. SP1 6.8.0/circuit v6.1.0: strict exit 1 with marker +
  native reject; minimal 12,593,166 cycles, parity PASS. Pico v1.1.6: strict
  non-zero guest halt + native reject; minimal 179,895,134 cycles, parity PASS.
  These are local builds/executions, not Docker reproducibility or real proofs.
- Native DCAP: 29 unit + 8 frozen fixture/output tests pass. Bindings: 1;
  registry: 14; utilities: 10. Rust verifier examples compile.
- Broad legacy Go/Rust online tests fail without RPC access and are not
  reported as passes.
- RISC Zero strict/minimal guests each execute five frozen signed quotes with
  native parity (10 positives), and reject eight SGX mutations each (16 negatives).
  Local build/execution is not Docker reproducibility or cryptographic proof acceptance.
- Pico strict/minimal each execute the same five frozen quotes with native parity
  (10 positives). No new Pico proof or on-chain acceptance is claimed.
- SP1 6.8.0 strict/minimal each execute all five frozen signed quotes with native
  journal parity (10 positives), and reject eight SGX mutations each (16 negatives).
  Host library/examples pass locked offline checks; ELF-version guard test passes.
  These are local builds/executions, not Docker reproducibility or real proofs.
- RISC Zero proof/compression/handoff runners now accept explicit minimal mode;
  all RISC Zero feature-selected examples compile after the host lock update.
- Deployment coordinator helper tests: 4; publisher tests: 16. Docker harness
  argument/archive tests pass using fake tools, not actual Docker builds/proofs.
- 2026-09-21 Hoodi fork acceptance (public RPC from chainlist:
  rpc.hoodi.ethpandaops.io; pin block 3666000/hash
  0x507bec8bb301dc25d57e09fee024cf8a099db7e8ee318c483591fed3b738a57f,
  profile `hoodi-osaka`). Anvil 1.5.1 reports Prague for chain 560048 but does
  not execute the P-256 precompile (0x100) under Prague; Hoodi's live state
  (successful P-256 collateral upserts, production verifiers) requires it, so
  the reviewed local runtime selects Osaka explicitly, same pattern as the
  Sepolia profile. One-click isolated deployment via
  `anvil-deploy.mjs ... hoodi-osaka` passed (32 transactions): new
  Router/PCKHelper/AttestationV2 + V3/V4/V5 verifiers, five shared DAO reuse,
  eval 18-21 versioned clones (Hoodi has no eval 17), additive reader grants,
  independent SP1Groth16VerifierV6 (`DCAP_SP1_V2_VERIFIER=deploy`), strict
  default SP1 program 0x0081c6c2…07d64, minimal 0x0001ed57…0f4d registered
  without default change; RISC Zero left unset (Hoodi legacy has no RISC Zero
  route; zero address recorded). Only one shared-state write was needed:
  upserting the frozen fixture PCK CRL over Hoodi's older 2026-09-10 10:50
  generation (rollback rule satisfied). Manifest readback passed (runtimes,
  immutables, owners, reader grants, versioned clones, paused state, program
  modes; legacy Hoodi Router is an older deployment revision, recorded not
  failed). Go SDK raw E2E (3 fixtures x explicit/default, events, three
  negatives each) and the Rust SDK parity runner passed with byte-identical
  gas; gas report reconciled; compare-gas legacy/V2 raw pairs and read-only
  isolation verification passed with snapshot restoration. Local program IDs
  above are host-build IDs for fork testing only; real registration still
  requires the P1 Docker paired builds.
  Known Hoodi state quirk: the shared resolver's FMSPC TCB content for the
  fixture keys was refreshed to the 2026-09-20 generation while the eval-20
  DAO content hashes still match the frozen 2026-09-11 fixture documents, so
  on-chain verification of the frozen journals passes but off-chain SDK
  collateral acquisition (both Go and Rust, byte-identical) returns the newer
  documents and cannot native-verify at the frozen fixture timestamps. The
  cross-SDK acquisition parity runner (`fork_v2_collateral`) therefore stops
  at native verification on this pin; it is an input-environment mismatch,
  not an SDK divergence. Acquisition with a current timestamp against fresh
   collateral remains the real-deployment flow and was validated end-to-end on
   this fork: Go-acquired input (re-timestamped to current time) passed native
   strict verification and RISC Zero strict guest execution parity (317-byte
   V5 journal).

Local-build program identifiers (host builds, not Docker-reproduced; real
registration must use the P1 paired-build return IDs):
- SP1 6.8.0 / circuit v6.1.0 verifying key = program ID: strict
  `0x0081c6c2dc56439de0802bc8202216b5ba07e345aecdf1287f5ed0dc77207d64`,
  minimal `0x0001ed575e95b9e18c45c6e6ae6fff12d056d2f05b744550000e5abb06820f4d`.
- RISC Zero 3.0.3 image ID: strict
  `0x1fa90a0e57878505b9f4360091c6307c3867fc67727c4fcb079d47a7ba8988af`,
  minimal `0xa255b04cbc91a18780345f47e9ff134100c0e4bbcccc99b7d6716b135928a520`
  (Hoodi has no legacy RISC Zero verifier route; a reviewed R0 verifier must be
  deployed before any RISC Zero registration).

Real Hoodi test deployment (2026-09-21, user-authorized, P4 scope): coordinator
broadcast 32 transactions from `0xC71263FB6808B971743C23F8F94b23AE3289f12f`
(keystore `hoodi-deployer`), source-verified on Hoodi Etherscan and published to
`deployment/v2.0/560048` (sourceCommit `7e4e95b`; `current` untouched). New
addresses: `AutomataDcapAttestationV2` `0xc36ad0ebcedb5e9cd04db3909ec8b3cacb2f74f1`,
`PCCSRouterV2` `0xfd55392f16f212c01039dab8dc0625baecd443d8`,
`PCKHelperV2` `0x49ff089cf2f7007de085f208acd4d1edbbad06ca`,
`V3QuoteVerifierV2` `0xd458714604ec31333bb055e6f9ed2060cbd0cf7e`,
`V4QuoteVerifierV2` `0x51213e3c04cb6aec60f49d7749b391fb2bea604b`,
`V5QuoteVerifierV2` `0x484f4da8b9fa75d61ea83cecf495b3fb1d42034e`,
`SP1Groth16VerifierV6` `0x2546664e37345ea71c579961ec2ce56d0d967f50`.
Registered SP1 strict default `0x0081c6c2…07d64` + minimal `0x0001ed57…0f4d`
against the independent v6 verifier; RISC Zero unset (no reviewed verifier);
ZK unpaused for backend 2 after program/verifier configuration. Ownership of
the Router and AttestationV2 was transferred onchain to the legacy owner
`0xDf841B239bE7a6b37366005107069b7410da4Ff9` (readback confirmed). Coordinator
fixes discovered by this first real broadcast (both committed): Foundry 1.5.1
sig-named broadcast artifacts, and explicit `--compiler-version` for
verification. Deployment used the local-build program IDs (P1 Docker
reproducibility remains skipped by explicit user decision). Pending: on-chain
raw/ZK transaction verification against the real deployment (ZK needs real
compact proofs, see P2) and operator commit of the new registry record; the
PCCS submodule deployment file carries an uncommitted `PCKHelperV2` entry by
coordinator design.

Remaining before this revision is considered complete:

1. Validate the Go v6 transport against a returned genuine v6 network proof,
   including cryptographic verification using a trusted verifier. Offline codec,
   truncated/malformed response and version-binding tests pass; no paid network
   request was submitted. Do not relabel v5 proof bytes or IDs.
2. Repeat independent official Docker builds for both modes and extend the
   verified Alibaba V5 guest policy matrix (2026-09-21, see Verified) onto
   those paired artifacts via `verify-current-guests.sh`, which now includes
   the mode-divergent `alibaba-v5` cell. The native, Solidity and local guest
   policy cells are frozen; the Docker cells are not.
   The v6.8.0 AMD64
   image manifest is pinned to
   `sha256:6df25c1a71451b51488534fb94a495ffe456c05921f79c4bcb8ccafe2810870c`.
   Old Mac core/outer proof handoffs are disabled; v6 uses the full SDK runner,
   with no accepted intermediate-checkpoint resume workflow yet.
3. Regenerate real compact strict/minimal proofs with those exact artifacts,
   then run one complete Sepolia fork including the new coordinator,
   raw/ZK/SDK, rejects and gas. The standalone historical Anvil/gas/replay
   scripts (`scripts/fork-dcap-v2/anvil-deploy.mjs`, `manifest-readback.mjs`,
   `negative-gas.mjs`, `compare-gas.mjs`, `gas-report.mjs`,
   `legacy-sp1-replay.mjs`) were migrated on 2026-09-21 to the compact V2
   isolated stack (new Router/PCKHelper/AttestationV2, no shared Router
   reconfiguration, compact journal offsets, V2 program modes, 356-byte SP1 v6
   proof framing). The retired SP1 v5 checkpoint/gnark tools and the
   inline-body `proof-matrix.mjs` now fail closed. These are static/script
   migrations only; no fork run has exercised them yet: this VM now has Anvil
   (1.5.1) but no outbound network access to any RPC, so a pinned Sepolia fork
   cannot be started here. Run the rehearsal on a machine with reviewed RPC
   access per the README.
4. Only after explicit authorization: deploy a new Hoodi test instance, read back
   and publish its distinct addresses. Existing test addresses and user-provided
   `deployment/v2.0/560048/manifest.json` have not been changed.

No live deployment, transaction, submodule deployment rewrite, git commit or push
has been performed in this checkpoint.
