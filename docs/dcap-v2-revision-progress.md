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
- Isolated deployment coordinator, checkpointed broadcasts, signer/resolver
  inventory, finalized readback, source verification and versioned publication.
  Helper/publisher unit tests pass; full coordinator end-to-end rehearsal is pending.
- Independent SP1 v6.1.0 Groth16 verifier deployment option (SDK 6.8.0), pinned
  upstream submodule source. Existing gateway/verifier routes remain unchanged.
  Foundry isolates its upstream Solidity 0.8.20 unit from DCAP Solidity 0.8.27.

Verified:

- Full Foundry suite: **117 passed, 0 failed, 2 skipped** (Sepolia fork requires
  `DCAP_FORK_RPC`, Story regression requires `STORY_RPC_URL`). Legacy proof tests
  in that total are not new compact-guest proof acceptance. Runtime: 19,818 bytes.
  Final rerun passed after sequential per-file compilation. A preceding bulk
  recompilation was killed with SIGKILL while host swap was full; that interrupted
  attempt is not counted as a pass. All DCAP compilation remains pinned to 0.8.27.
- Native DCAP: 29 unit + 8 frozen fixture/output tests pass. Bindings: 1;
  registry: 14; utilities: 10. Rust verifier examples compile.
- Go compact client/parser/registry and SP1 legacy/v6 transport tests pass;
  all Go packages compile. Broad
  legacy Go/Rust online tests fail without RPC access and are not reported as passes.
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

Remaining before this revision is considered complete:

1. Validate the Go v6 transport against a returned genuine v6 network proof,
   including cryptographic verification using a trusted verifier. Offline codec,
   truncated/malformed response and version-binding tests pass; no paid network
   request was submitted. Do not relabel v5 proof bytes or IDs.
2. Complete production-policy strict-reject/minimal-accept guest matrix and
   repeat independent official Docker builds for both modes. The v6.8.0 AMD64
   image manifest is pinned to
   `sha256:6df25c1a71451b51488534fb94a495ffe456c05921f79c4bcb8ccafe2810870c`.
   Old Mac core/outer proof handoffs are disabled; v6 uses the full SDK runner,
   with no accepted intermediate-checkpoint resume workflow yet.
3. Regenerate real compact strict/minimal proofs with those exact artifacts;
   migrate standalone historical Anvil/gas/replay scripts, then run one complete
   Sepolia fork including the new coordinator, raw/ZK/SDK, rejects and gas.
4. Only after explicit authorization: deploy a new Hoodi test instance, read back
   and publish its distinct addresses. Existing test addresses and user-provided
   `deployment/v2.0/560048/manifest.json` have not been changed.

No live deployment, transaction, submodule deployment rewrite, git commit or push
has been performed in this checkpoint.
