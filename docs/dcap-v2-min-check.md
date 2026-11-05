# V2 minimal workload checks and Keccak quote commitment

This is a revision of the unreleased V2 feature, not a change to deployed V1.
OutputV2 remains unreleased format 2.1, with the compact 317-byte header defined
in dcap-v2-design.md. Both the earlier SHA-256 and inline-body 2.1 artifacts are
incompatible. Do not register their program IDs as current V2 IDs.

## API and acceptance

```solidity
verifyAndAttestOnChainV2(bytes rawQuote)
verifyAndAttestOnChainV2(bytes rawQuote, uint32 tcbEvaluationDataNumber, bool minCheck)
verifyAndAttestWithZKProofV2(bytes journal, ZkCoProcessorType backend, bytes proof)
verifyAndAttestWithZKProofV2(bytes journal, ZkCoProcessorType backend, bytes proof,
    bytes32 identifier, uint32 tcbEvaluationDataNumber, bool minCheck)
```

The short selectors remain strict. The two long draft selectors are replaced,
not retained as additional overloads. Rust/Go clients require the final boolean;
general SDK routing and fork scripts explicitly pass `false`.

| Check | Strict (short calls / false) | Minimal (true) |
| --- | --- | --- |
| SGX/TDX DEBUG unset | Required | Application decision |
| TDX reserved attributes zero | Required | Application decision |
| TDX SEPT_VE_DISABLE set | Required | Application decision |
| TDX 1.5 MR_SERVICE_TD zero | Required | Application decision |
| Quote/certificate/collateral signatures, root trust and revocation | Required | Required |
| V2 framing/DER, PPID/PIID presence and CA semantics | Required | Required |
| TCB matching, revoked/unknown rejection, PCS v4/TCB Info v3 | Required | Required |
| Canonical journal, proof/ID/route/pause checks and collateral binding | Required | Required |

Minimal is V1-like only for the listed workload attributes, not a switch to V1
verification. Applications must choose the mode themselves rather than blindly
forwarding an untrusted user's flag. A successful minimal result is authenticated,
but is not a claim that the workload meets production attribute policy.

OutputV2 carries `keccak256(quoteBody)`, not the body itself. Raw methods return
`(bool success, bytes output, bytes quoteBody)`; ZK methods return `(bool, bytes)`.
Applications must hash the separately supplied body and compare it with the
authenticated `quoteBodyHash` before any custom attribute or measurement checks.
Neither mode adds freshness, maximum age, challenge binding or application
measurement allowlists. `AttestationSubmittedV2` records the selected mode and
program ID (zero for raw), plus compact output, never the full body. The output
alone does not encode mode; applications must use a trusted call/event context.

## Guest and hash semantics

Every backend has two separate binaries/IDs, strict and minimal. Each binary fixes
its policy at compile time and commits compact OutputV2. The input ABI stays
`(bytes collateral, bytes quote, uint64 timestamp)` with no caller-controlled mode.
The registry binds each ID to one immutable mode; ZK calls enforce exact ID/mode
matching. Registering an ID never changes the strict-only default. The contract
does not recheck workload attributes from a ZK body because no body is in journal.
Raw strict checks remain on chain. Native `verify_guest_input_v2` is strict;
`verify_guest_input_v2_minimal` is minimal.

`fullQuoteHash` at bytes `[253, 285)` is Keccak-256 of the exact raw quote on
both raw and guest paths. RISC Zero still verifies SHA-256 of the journal.
Fixture/file integrity SHA-256, backend-native IDs and proof digests are not
changed into Keccak hashes.

Five frozen public quote fixtures retain their signed inputs and collateral.
Their expected journals now use the compact layout, including bodyHash instead
of the body, revised offsets and expected-journal integrity digests.
Tests compare the revised journals across native Rust and Solidity;
tests never regenerate their own expected output.

## Regression and release gates

Mode tests cover SGX DEBUG, TDX 1.0/1.5 attributes, MR_SERVICE_TD and the same
journal through all three backend adapters. Adapter unit tests use mocks and
are not real ZK proof acceptance. The real signed Alibaba V5 quote exercises
strict rejection/minimal acceptance in Solidity. Fresh dual-program guest
execution of a non-production signed fixture remains a separate acceptance gate.
Public V3/V4/V5 fixtures check byte parity and authentication/framing/time
negatives under both modes.

Local regression commands (from repository root):

```sh
forge test --root evm --match-path 'forge-test/*V2*.sol' \
  --no-match-contract 'DcapV2Fork|CrlV2AeneidFork'
cargo test --manifest-path rust-crates/Cargo.toml -p dcap-rs --locked \
  --lib --test guest_fixtures_v2 --test output_v2
cargo check --manifest-path rust-crates/Cargo.toml -p automata-dcap-verifier \
  --examples --locked
(cd go-sdk && go test ./packages/godcap/attestationv2 ./packages/godcap/parser)
```

### Historical inline-body regression checkpoint (2026-09-16)

The following results predate the compact revision and do not validate its new
guests, IDs, proof formats or deployment. See dcap-v2-revision-progress.md.

Run against the edited working tree based on DCAP `357f5d5`, with the existing
PCCS checkout `75c7673` preserved. Solidity used Foundry 1.8.1, solc 0.8.27,
optimizer 200, via-IR and Paris bytecode. This is not a frozen release commit.

- Solidity: 100 tests passed in smaller build groups: 73 non-fork V2 tests
  plus 27 parser/revocation/legacy regression tests. This includes three
  256-run framing/DER/truncation fuzz tests. All-at-once compilation was killed
  for memory pressure; the grouped runs passed. The legacy group includes
  existing RISC Zero/SP1/Pico proof fixtures, not proofs for the revised V2 guest.
- Native Rust: 37 DCAP unit/fixture/output tests, one bindings selector test
  and 10 utility/parser tests passed. The verifier examples compile with the
  updated signatures.
- Go: FeeV2/parser tests passed; every Go SDK package compiled with `go test
  ./... -run '^$'`. Fork-only SDK tests require their explicit environment.
- FeeV2 runtime size: 22,590 bytes (EIP-170 margin: 1,986 bytes).
- Updated `DcapV2ForkTest` compiles. Execution is **SKIPPED** without
  `DCAP_FORK_RPC`; this is not a new fork acceptance result.
- The broad legacy Rust test run had one external-data failure:
  `e2e_v5_quote` could not fetch its PCCS collateral. Seven other legacy
  integration cases passed; offline real V5 tests passed independently.

RISC Zero, SP1 and Pico local rebuilt guests each executed all five frozen
fixtures and matched the revised full journal (15 positive executions).
RISC Zero and SP1 also rejected all eight `--negative` mutations for ATA SGX V3
(16 negative executions). Pico remains local-only. All guest/build-driver lockfiles
were unchanged. These are execution checks, **not proofs**
and not canonical Docker release artifacts. RISC Zero execution required local
subprocess/IPC permission; no remote prover was used.

| Local development backend | ELF/program SHA-256 | Native program ID |
| --- | --- | --- |
| RISC Zero | `4ab656ec66c880edab82643b35d17f6a5fc138c274106e8563153387ba06035a` | `3d8a6b4ec33a73a033419418b4bd64870ac499d645b476bf3042f2f1052bdb3b` |
| SP1 | `4f0a1f03c70b0ca00d0a981ff75883b3617e347c75f73b0180dd2be52cd861f3` | `0069099f451589bc41851b2461503b52741f11970689d84c0b1d19312eadd3e8` |
| Pico (local-only) | `1ce43aa8b7788dcfaa7bb25e9f0b2350de7a90078507169be67f06b9a27daa5c` | `0061aa7307e49cb8e8311875d8855c50ef4dba637df9d519b806f196e7277fa2` |

Use the existing `v2_fixture export` command and backend `*_v2_execute` examples
to repeat these checks against a newly built explicit ELF; never infer a new
build's success from an older file already present in the artifact directory.

Before release, repeat the pinned paired-Docker builds and record new ELF hashes
and native IDs. Regenerate RISC Zero/SP1 real proofs and rerun Sepolia fork
raw/ZK/SDK acceptance, including both mode selections, rejects and gas. Prior
proof matrices, timings and gas reports are historical only. Pico remains
local-only and is not added to any production network.
