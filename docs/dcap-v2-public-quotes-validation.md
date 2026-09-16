# Public ATA SGX/TDX V2 validation — 2026-09-11

> Superseded checkpoint: the minCheck/Keccak revision changes guest semantics,
> fullQuoteHash and the long V2 selectors. Build IDs, proofs, fork acceptance
> and gas results below are historical, not acceptance for the current source.
> See [current revision and release gates](dcap-v2-min-check.md).

## Inputs and important framing difference

The two user-supplied public quotes are retained byte-for-byte under
[quotes](../evm/forge-test/assets/v2/quotes/README.md). Full signed collateral,
ABI inputs, expected journals, digests and provenance are frozen in
[fixtures](../evm/forge-test/assets/v2/fixtures/README.md). No private key,
prover credential, live transaction or deployment is involved.

| Input | Decoded bytes | Authentic positive input | Result at the frozen timestamp |
| --- | ---: | --- | --- |
| ATA SGX, Quote V3 / SGX body | 4,734 | Original supplied bytes | Accepted; TCB status `OutOfDate` (1) |
| ATA TDX, Quote V4 / TD 1.0 body | 8,000 | **Not** the full supplied bytes | Rejected: trailing quote bytes |
| Explicit TDX prefix | 4,935 | Exact declared quote prefix | Accepted; TCB status `UpToDate` (0) |

The original TDX includes **3,065 trailing zero bytes** beyond its declared
signature length. Extraction is a separate, explicit test-data operation:
every signed byte and signature is unchanged. Normal V2 verification never
strips padding. Rust, Solidity, RISC Zero and SP1 all reject that original
padded input. `fullQuoteHash` in the positive journal commits to the extracted
4,935-byte quote, not the original 8,000-byte buffer. Decoded-byte and textual
file hashes are distinct; the quote provenance document records the former.

Both snapshots use timestamp **1789139978 (2026-09-11T15:19:38Z)** and TCB
evaluation number **20**. Matching TCB Info and QE identities were fetched
from Intel PCS API v4 on 2026-09-11. Root/platform CRLs and the signing/root
certificates were reused from the authenticated `v5.json` snapshot of
2026-09-10; response issuer chains were independently compared with those
certificates. Native and Solidity full verification authenticate the combined
snapshot. Tests do not fetch fresh collateral or regenerate expectations.

Both PCK chains use Platform CA with `piidPresent=true`. These samples do not
add Processor CA/PIID-absent, V5, revoked-platform or provider-provenance
coverage. Passing verification does not mean `UpToDate`, freshness/challenge
binding, or acceptance by every downstream application policy.

## Completed checks

| Layer | Observed result | Coverage boundary |
| --- | --- | --- |
| Native Rust | 35 tests pass: 28 unit + 4 fixture + 3 OutputV2 | Five frozen fixtures; ATA positives and 8 negative mutations each |
| Solidity | 92 tests pass in 20 suites, including 19 new ATA tests | Real local PCCS deployment/upserts, P-256, chain/CRL checks, V3/V4 verification, FeeV2 output/events; not a fork |
| Go SDK | Parser, FeeV2 and registry packages pass | New ATA journal decoding, hash checks, exact round trips and malformed-output rejection; not RPC end-to-end |
| RISC Zero | 2 positive executions and 16 rejection checks pass | Canonical Docker program, real local `r0vm` 3.0.3 execution; not proof verification |
| SP1 | 2 positive executions and 16 rejection checks pass | Canonical Docker ELF, explicit CPU execution with SDK 5.2.2; not proof verification |
| Pico | 2 positive executions pass | Canonical Docker ELF, SDK 1.1.6 / KoalaBear; no negative/proof coverage in this runner; local-only |

All successful native/Solidity/guest outputs agree byte-for-byte on the full
OutputV2 **2.1** journal, including identity/presence, status, timestamp, quote
and collateral hashes, report body and advisory list. Solidity also checks the
FeeV2 event payload, major/minor indexed topics, success and backend value.

The eight shared quote/input rejection cases are changed signed body, changed
quote signature, trailing zeros, truncation, unsupported quote version,
oversized signature length, pre-validity time and post-validity time.
Five host guards also reject development mode or disabled SP1 VK/shape checks
before reading any input. Fixture-tool checks pass for exact extraction,
overwrite refusal, non-padded extraction refusal, padded preparation refusal
and authenticated preparation parity. These are diagnostic-tool checks, not
additional proof-verification successes.
Solidity must return failure or a nonempty non-panic revert, without a success
event. RISC Zero/SP1 must report the guest validation failure, not transport,
cycle-limit or arbitrary VM errors. These are input rejection checks: changing
a signed quote does not produce a valid proof of successful verification.

### Canonical program execution measurements

Guest source remains `81646e5754a8124d4a70a483882f11b515c98c7b`. This follow-up
changes fixtures, tests, host examples and documentation, not guest source,
cryptographic SDK versions, lockfiles or registered IDs. The canonical programs
are the previously paired Docker artifacts, not the host-native candidates.
See the [Docker build evidence](dcap-v2-container-rebuild.md) for image/source
provenance and the separate meaning of artifact SHA-256 and native program ID.

| Backend | Program SHA-256 | Native program ID |
| --- | --- | --- |
| RISC Zero | `0560682c1b2edee108406f66cd3d174671941da2267846ebd076e6b335762371` | `0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b` |
| SP1 | `95f7c4bd575fe4bbe9bcb55538941213c5c7cf49bd929dde811b9fb85ad2f69f` | `0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170` |
| Pico | `8d0dc7c137e1a2b3f336acc05ac82125833f385201cd11a5bfbf1e02128b31b4` | `0x000e95d6b7f85b7a9302081b512ab1dff0fad9759b89411d083760c7d554efd6` |

| Backend | SGX cycles | TDX cycles | SGX / TDX journal bytes |
| --- | ---: | ---: | ---: |
| RISC Zero | 15,307,938 | 14,797,269 | 833 / 873 |
| SP1 | 15,440,460 | 14,938,128 | 833 / 873 |
| Pico | 180,869,982 | 180,369,323 | 833 / 873 |

Cycle definitions differ between VMs; RISC Zero reports user cycles, excluding
continuation/proof padding. Forge test gas includes harness work and is **not**
the deployment/upsert/verification gas breakdown required by fork acceptance.

## Real proof attempts — separate from the passing execution checks

Added and compiled explicit-local, non-overwriting diagnostic runners:

- [`risc0_v2_prove_local`](../rust-crates/libraries/zkvm/examples/risc0_v2_prove_local.rs):
  real composite receipt, receipt/image-ID verification, complete journal
  comparison, then modified journal/wrong image ID/modified seal rejection.
- [`sp1_v2_prove_local`](../rust-crates/libraries/zkvm/examples/sp1_v2_prove_local.rs):
  real CPU core proof, proof/key verification, complete journal comparison,
  then modified journal/wrong verifying-key rejection. The extended retry
  additionally checks modified proof-commitment rejection and enforces the
  SDK's default FRI query count.

Both accept `PROGRAM INPUT OUTPUT [--verify]`; existing receipts/proofs can be
rechecked without reproving. Successful compilation is not evidence that the
cryptographic or proof-negative checks ran. A composite/core proof is also not
an EVM Groth16/Plonk proof or an assertion of its zero-knowledge properties.

This ARM64 worker has approximately 15.6 GiB RAM. Diagnostic host examples
were built in the existing **unoptimized dev profile** with locked/offline
dependencies and a two-thread LLD link; this is not a proving benchmark.

| Attempt | Limits/settings | Observed outcome |
| --- | --- | --- |
| RISC Zero, SGX | 600 s, 10 GiB virtual memory, Rayon 2, segment size 2^18 | Timeout, exit 124; no completed receipt, cryptographic checks not reached |
| SP1, SGX | 600 s, 7 GiB virtual memory, Rayon 2, shard size 2^18, batch 1, single-buffer pipeline | Timeout, exit 124; no completed proof, cryptographic checks not reached |

No TDX real proof was generated in the initial bounded run. At that point no
real V2 proof acceptance or proof-tampering rejection was established. The
subsequent serial retry below supersedes that local-proof status, but does not
establish universal-verifier/FeeV2 proof compatibility.
Timeout/resource limitations are not a rejection of the quote or a
proof-system correctness failure. Retry on an appropriate optimized proving
worker with an explicit resource budget; do not use mock proofs, disable
cryptographic checks, change native IDs, or silently choose a paid prover.

### Extended serial retry (2026-09-11)

The user first requested one hour per backend, then explicitly allowed longer
waiting while computation continued normally. The two-thread, one-hour wrapper
was stopped deliberately before its deadline and before SP1 started, so that
its fixed timer could not discard a nearly completed proof. Its logs remain
under `/tmp/dcap-proof-hourly.LOwQLe`; this was a control change, not a proof
verification failure. No completed receipt was deleted.

The replacement runs **RISC Zero then SP1, never concurrently**, without a
wall-clock deadline. It uses four Rayon threads on this 12-CPU worker and the
same small segments/shards and single-buffer SP1 pipeline. The initial 10 GiB
virtual-memory ceiling was retained for RISC Zero and revised for the SP1
resource retry described below. Programs, inputs, SDKs, locks and cryptographic
checks are unchanged. RISC Zero used the existing dev host plus the installed
`r0vm`; SP1's initial dev-host retry was deliberately stopped to compile an
optimized release host before continuing. Its diagnostic example gained SDK
progress logging, a modified-commitment negative check and an explicit guard
against lowering the default FRI query count. No guest code, SDK or production
verification rule changed.

| Backend / input | Observed outcome | Elapsed / maximum RSS |
| --- | --- | --- |
| RISC Zero / ATA SGX V3 | **PASS**: real composite receipt, exact 833-byte journal, changed journal/wrong image ID/changed seal all rejected | 1:03:19 / 3,667,272 KiB (~3.50 GiB) |
| SP1 / ATA SGX V3 | **PASS**: real CPU core proof, exact 833-byte journal, changed journal/wrong verifying key/changed proof commitment all rejected | 11:55.22 / 7,518,080 KiB (~7.17 GiB) |

RISC Zero started at `2026-09-11T16:23:01Z` and exited with status 0 at
`17:26:20Z`. It proved 86 execution segments and a Keccak assumption before
composite receipt verification. The saved bincode receipt SHA-256 is
`e360696731f61e585a9cfb63cc6c64e4e853c04092c239ab1fddd0d0153d5c5f`.
This is a cryptographically verified **composite** receipt, not an EVM
Groth16 seal and not evidence that the existing universal verifier or FeeV2
has accepted a V2 proof. The initial SP1 dev retry started at
`2026-09-11T17:26:20Z`; it was not run concurrently with RISC Zero. Its observed
execution checkpoints advanced, without a proof/verification error, before
the host optimization restart. A checkpoint is not a verified proof shard.
The release host started at `2026-09-11T17:44:50Z`. Its first build hit an
upstream VK-map download error (HTTP 400); copying the already cached file
after verifying the SDK-pinned SHA-256
`5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8`
allowed the SDK's own hash-checked build to continue. No empty map, `DOCS_RS`,
disabled VK check or dependency upgrade was used.

That first release-host proof attempt ended at `17:51:30Z`, exit 134, after a
482,064,780-byte allocation failed. Elapsed time was 6:40.05 and maximum RSS
was 4,719,792 KiB (~4.50 GiB). Execution traces had reached batch 58, but no
completed proof or cryptographic success was produced. RSS does not include
all reserved virtual address space: this is consistent with the 10 GiB
address-space ceiling/allocator reservations, not evidence of an invalid
quote. The old sampler did not record virtual size, so it does not prove the
precise allocator cause.

The next release-host attempt started at `17:56:01Z` with
`MALLOC_ARENA_MAX=2`, a 24 GiB **virtual address-space** ceiling, unchanged
four-thread/single-buffer settings and no time limit. A one-second watcher
records RSS, virtual size and system available memory; it terminates only
this prover if RSS exceeds 8 GiB or system available memory falls below
1.5 GiB. This is a sampled safety check, not a kernel-enforced physical RAM
limit. No global memory setting, cryptographic parameter, canonical guest,
SDK or input changed.

The memory-tuned SP1 attempt completed successfully at `18:07:57Z`, exit 0.
It advanced beyond the prior failing batch, produced a nonempty real core
proof, cryptographically verified it with the canonical ELF-derived key,
matched the entire journal, and passed all three proof rejection checks.
The saved proof is 115,484,043 bytes, SHA-256
`3b601fb250ecbc739f03a79a03eee8979cc2d541d8b61e6582077aa4101db721`.
No watchdog threshold fired. A sampled virtual size of 16,861,644 KiB during
the final trace batch exceeded the previous limit while RSS was only
4,113,292 KiB, illustrating why address-space and physical-memory budgets
must not be conflated.

Both successful runs use the **original SGX V3** quote and fixed collateral
timestamp; no TDX or V5 real proof was generated in this retry. The SP1 core
proof, like the RISC Zero composite receipt, is not the compressed proof
format accepted by an EVM universal verifier. Local cryptographic and
tampering checks are now established for these two SGX artifacts; EVM proof
compression, every intended proof route and FeeV2 integration remain open.

After archiving, fresh processes loaded the extracted artifacts and repeated
the positive verification, whole-journal comparison and all three negative
checks per backend: **both passed again**, exit 0. RISC Zero read-back took
1:05.80 (dev host), SP1 0:13.85 (release host). This tests saved artifact
round trips with the same SDKs, not independent cryptographic implementations.
Proofs and retry/build/resource/read-back logs are retained locally in optional
ignored archives. Git keeps exact runner sources, text hashes, this result
summary and the [archive-free repeat procedure](evidence/dcap-v2/2026-09-11/ata-proofs/README.md#repeat-without-the-archives).
The summary is not a substitute for obtaining and cryptographically checking
the historical artifacts when an independent audit of that exact run is required.
All prover and watcher processes have exited; no background computation remains.

## Repeatable commands and fork handoff

Export either authenticated fixture offline, using a new output directory:

```sh
ata_input_dir="$(mktemp -d /tmp/dcap-ata-inputs.XXXXXX)"
for sample in ata-sgx-v3 ata-tdx-v4; do
  cargo run --locked --offline --manifest-path rust-crates/Cargo.toml \
    -p dcap-rs --example v2_fixture --target-dir rust-crates/target -- \
    export "evm/forge-test/assets/v2/fixtures/${sample}.json" \
    "$ata_input_dir/${sample}.bin"
done

CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test --locked --offline \
  --manifest-path rust-crates/Cargo.toml -p dcap-rs --lib \
  --test output_v2 --test guest_fixtures_v2 --target-dir rust-crates/target
forge test --root evm --match-contract 'PublicAta(SgxV3|TdxV4)Test' -vv
forge test --root evm --no-match-contract CrlV2AeneidForkTest -vv
go test ./go-sdk/packages/godcap/parser ./go-sdk/packages/godcap/feev2 \
  ./go-sdk/packages/godcap/registry
```

Pass exported inputs plus the verified canonical program to the documented
[RISC Zero](../rust-crates/libraries/zkvm/methods/risc0/README.md),
[SP1](../rust-crates/libraries/zkvm/methods/sp1/README.md) and
[Pico](../rust-crates/libraries/zkvm/methods/pico/README.md) runners.
RISC Zero requires local subprocess/loopback IPC, not a remote service.
RISC Zero/SP1 execution runners accept `--negative`; the proof runners do not.
Do not replace canonical programs with host rebuilds when repeating this check.

The mandatory [full fork phase](dcap-v2-fork-validation.md) remains deferred:
target-chain inventory, deployment/configuration/authorization, upserts,
automatic evaluation selection, raw and real-ZK paths, supported SDK RPC
flows, route freezes/pauses, migration/rollback and gas/cost breakdown.
`CrlV2AeneidForkTest` was explicitly excluded, not silently counted as passed.
Use snapshots/blocks consistent with signed collateral validity; a future
fork may need new collateral and a separately reviewed new expected journal.
Pico remains local-only, with no added network registrations or deployments.

The [validation record](evidence/dcap-v2/2026-09-11/ata-quotes/README.md) retains
small text manifests and describes optional local archives of logs, exported
inputs and downloaded PCS responses. Complete archives are not included in
this follow-up Git commit; the checked-in fixtures already hold the signed
collateral and allow offline reconstruction of the ABI inputs.
Original user attachments and earlier Mac archives/session logs are unchanged.
