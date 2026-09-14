# Sepolia V2 acceptance — 2026-09-14

**PASS: the scoped six-cell real-Groth16 / single-Sepolia V2 E2E.**
This is not live-deployment approval or a claim that every legacy/rollout
follow-up is closed. All deployment, configuration and SDK transactions ran on
an isolated local fork; the final FeeV2 ZK state is **paused**.

## Scope and reproducibility

- Chain **11155111**, origin block **11689923**, hash
  `0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096`.
  Upstream: `https://rpc.sepolia.ethpandaops.io`; Osaka execution, Paris bytecode,
  Solidity 0.8.27, via-IR, 200 optimizer runs.
- Source HEAD `31676153915c2ae00dbc7de376f1e36b463280b2` plus the uncommitted
  acceptance changes; PCCS `f1406ef479560ad888960899b95383f026c76526`.
  **The final release commit is not frozen.**
- Canonical Docker guest source baseline:
  `81646e5754a8124d4a70a483882f11b515c98c7b`. The final runner fix does not
  change either guest, native ID, guest lock or the tested host lock.
  Paired-container reproducibility is recorded
  [separately](dcap-v2-container-rebuild.md); proof bytes are randomized and
  are not a reproducible-build comparison.
- Existing RISC Zero `73c457ba` and SP1 `a4594c59` Groth16 routes were reused.
  No new setup, universal verifier, production registration or default was added.
- Fixtures: authenticated ATA SGX V3, ATA TDX V4 and Google TDX 1.5 V5.
  TDX V4 uses the exact **4,935-byte** declared prefix; the original 8,000-byte
  buffer still rejects. Google V5 is unmodified. All three use Platform CA
  with PIID present and frozen authenticated verification times.

## Completed gates

- Six native Groth16 verifications, complete expected journals and tamper/wrong-ID
  or key negatives; six existing-universal-verifier/FeeV2 proof cells.
- The final SP1 V5 full contract suite: **16 passed, 0 failed, 0 skipped**.
  The same suite was exercised for the preceding proof cells.
- **24 real ZK SDK transactions**: six cells × Go/Rust × explicit/default.
  Full output/event parity; both SDKs restore the original pause state.
- **12 raw SDK transactions**, three signed raw fixtures, legacy/V2 coexistence,
  collateral upserts, actual deployment-script simulation, role/helper guards
  and rollback. Go acquisition: 6 cases; Rust direct/multicall acquisition:
  12 cases, plus native verification of all six Go inputs.
- **63 selected positive deployment/SDK receipts and traces** reconcile:
  27 deployment/configuration/upsert + 12 raw + 24 ZK. SDK pause administration
  is outside this selected count.
- **Six negative runs**, each containing 11 rejection transactions, two positive
  controls and four administration transactions: **66 rejections**, not 66
  distinct scenarios. False returns and reverts are distinguished; neither
  emits an accepted event. Every run restores its starting snapshot.
- **29 comparison transactions / 15 cold-warm pairs**, with helper rollback,
  legacy/V2 replay and exact snapshot restoration.
- All five deployed runtimes/immutables, owner, Router components, four reader
  authorizations, fees and enumerated legacy/V2 IDs match the local manifest.
  Final readback block `0xb2601a`, hash
  `0x17f322aecffc087ad13c5c848883174799f9cb0b86d247c47b16f90e7d185d30`; V2 is paused.

## Receipt gas

The explicit/default values below match between Go and Rust. They are actual
local transaction receipt gas, not the Foundry test-method cost.

| Backend | Signed fixture | Explicit | Automatic |
| --- | --- | ---: | ---: |
| RISC Zero | SGX V3 | 492,092 | 694,055 |
| RISC Zero | TDX V4 | 490,484 | 692,435 |
| RISC Zero | Google V5 | 492,548 | 694,512 |
| SP1 | SGX V3 | 467,098 | 669,085 |
| SP1 | TDX V4 | 465,490 | 667,465 |
| SP1 | Google V5 | 467,555 | 669,543 |

| Raw fixture | Existing Fee | FeeV2 legacy selector | V2 explicit | V2 vs existing Fee |
| --- | ---: | ---: | ---: | ---: |
| SGX V3 | 4,896,198 | 4,899,785 | 5,144,791 | +5.08% |
| TDX V4 | 4,118,757 | 4,110,841 | 4,347,249 | +5.55% |
| Google V5 | 3,658,410 | 3,645,527 | 3,884,101 | +6.17% |

Raw V2 explicit-call component breakdown (exclusive, sums to each receipt):

| Bucket | SGX V3 | TDX V4 | Google V5 |
| --- | ---: | ---: | ---: |
| entrypointAndTransactionAccounting | 152,870 | 152,528 | 155,806 |
| quoteVerifierExclusive | 1,413,958 | 1,325,351 | 1,292,594 |
| router | 505,992 | 310,219 | 228,627 |
| pckParser | 729,929 | 727,790 | 727,958 |
| sha256 | 3,432 | 3,588 | 3,636 |
| collateralDaos | 252,061 | 225,463 | 196,197 |
| collateralStorage | 1,433,212 | 1,178,013 | 969,844 |
| crlHelper | 89,547 | 89,547 | 89,547 |
| p256 | 34,500 | 34,500 | 34,500 |
| tcbHelpers | 529,290 | 300,250 | 185,392 |

For V5 ZK, RISC Zero / SP1 respectively spend **211,750 / 193,300** on BN254
precompiles and **23,332 / 17,229** in exclusive universal/SNARK verifier calls.
Both spend **32,001** on Router, **36,314** on collateral DAOs and **85,818** on
collateral storage; the remaining entrypoint, SHA-256 and quote-verifier buckets
are recorded in the local gas summary. Component accounting does not isolate
every private certificate/policy function or event. Intrinsic/calldata costs are
a separate view, not added to these already reconciled totals. Cold/warm figures
in the matrix are two calls inside a probe transaction, not standalone receipt
gas. No L2 fee, fiat price or worst-case rejection-gas bound is inferred.

## SP1 V5 runner correction and final proof

The returned Mac outer was valid only with the earlier runner's erroneous
global `FRI_QUERIES=100`. Official SP1 5.2.2 defaults are core/inner **100**,
shrink **50**, outer **25**. Overriding all stages produced a witness of
**89,111** elements against the existing official setup's **24,235**.
This was a supplied test/handoff-script error, not a bad quote or guest.

The helpers now reject any presence of `FRI_QUERIES`; the handoff runner no
longer sets it. The original compressed proof reverified under official defaults.
Only shrink/outer and final Groth16 were rerun. The obsolete Mac outer rejects
under those defaults; the old witness rejects before proving allocation.

The corrected outer completed locally in **8:31.12**. Official ARM64 Groth16
completed in **93 seconds** including startup, with a sampled Docker maximum of
**8.787 GiB**. CPU/Go garbage-collection controls limited memory without changing
proof parameters. Strict native import and the final existing-verifier/FeeV2
tests then passed. **No further Mac action is needed.**

The final immutable SP1 V5 EVM JSON SHA-256 is
`edf9fdc7c924dcac3c76142d353a2d86c8224990e0fb264e99781144ef08e71f`.
Its full 937-byte journal matches the RISC Zero V5 journal exactly.
The old Mac archive remains diagnostic evidence, not an accepted outer artifact.

## Evidence and remaining release gates

- [Proof/SDK matrix](dcap-v2-sepolia-proof-matrix.json), SHA-256
  `15282c386cb683abf45283b36f2cba35a0fd017aa5a38584e9a29a9a2f57bd6e`.
- [Local runtime/configuration manifest](dcap-v2-sepolia-local-manifest.json).
- [Rerun recipes](../scripts/fork-dcap-v2/README.md) and
  [chronological execution record](dcap-v2-fork-progress.md).
- Full receipts, traces, native proofs and logs remain ignored/local. The final
  local gas summary SHA-256 is
  `d755bc2ca68bf298086b9a2907fae46fb99a87e2772249c4102c79d2cf2c133c`; the checked-in matrix binds that summary.

Before proposing live deployment: review/commit the changes, freeze the final
release manifest/artifacts, and read back configuration/permissions/IDs/routes/
freezes/fees for each **selected production target**. This is not another
all-network E2E requirement. Live broadcast/default promotion needs approval.

Historical RISC Zero/ATKJ full-proof replay and the archive-dependent Story CRL
regression remain explicitly unclosed follow-ups in the
[checklist](dcap-v2-fork-validation.md). Registration migration or a successful
V2 proof is not evidence that those legacy proof paths pass.

No authenticated SGX V4/V5, TDX 1.0 V5 or Processor-CA/PIID-absent success is
inferred from these three fixtures. No remote-prover service, SP1 Plonk, downstream
application deployment or other-network full E2E is claimed. Pico is local-only;
Solana remains excluded.
