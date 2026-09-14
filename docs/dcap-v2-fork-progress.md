# Fork execution record — 2026-09-12–14

The scoped six-cell V2 / single-Sepolia E2E is complete; see the compact
[acceptance summary](dcap-v2-sepolia-acceptance.md) and
[proof matrix](dcap-v2-sepolia-proof-matrix.json). This is **not a release approval**. Live deployments,
registry/default changes and paid proving remain unauthorized. All writes below
are on isolated local forks. The full acceptance checklist remains in
[dcap-v2-fork-validation.md](dcap-v2-fork-validation.md).

## Coverage at this checkpoint

**Scope corrected on September 14:** complete E2E is required only on the
existing pinned **Ethereum Sepolia fork**, which supports both RISC Zero and
SP1. The earlier all-network E2E/gas/rollback wording was too broad. Other-chain
results below remain supplementary historical evidence, not required missing
E2E cells. Before production deployment, selected targets still need read-only
configuration/permission/route preflight; that is distinct from repeating E2E.

The completed real-proof matrix on Sepolia is:

| Existing input | RISC Zero Groth16 | SP1 Groth16 |
| --- | --- | --- |
| ATA SGX V3 | PASS | PASS |
| ATA TDX V4, exact declared 4,935-byte prefix | PASS | PASS |
| Google Quote V5 / TDX 1.5 (`v5.json`) | PASS | PASS |

SP1 V5 now passes official Groth16, the existing verifier/FeeV2 and both SDKs,
closing the last cell. Both backends use frozen signed collateral and have
native/raw/guest success coverage. The TDX transformation removes
only 3,065 trailing zero bytes outside the declared quote, without altering any
signed byte; normal V2 parsing still rejects the original 8,000-byte buffer.
Google V5 remains unmodified, with zero `MR_SERVICE_TD` and production-policy
acceptance. Fixed verification times do not assert current freshness.

Each passing cell is bounded to the pins and fixtures recorded below. None means
that every registered network or the complete rollout checklist has passed.

| Network | Authentic raw V3/V4/V5 | Real V2 ZK through reused verifier/FeeV2 | SDK transactions / cost coverage |
| --- | --- | --- | --- |
| Ethereum Sepolia | PASS | RISC Zero and SP1: SGX V3 / TDX V4 / V5 PASS | Go/Rust raw and all six real-proof cells PASS; receipt/trace gas |
| Hoodi | PASS | SP1 SGX V3 and TDX V4 PASS | Full SDK transaction rehearsal not run |
| Ethereum mainnet fork | PASS | No real-proof cell completed | Full SDK transaction rehearsal not run |
| OP Sepolia / Karst | PASS | No active RISC Zero/SP1 defaults at the pin; no backend added | Go/Rust raw PASS; 60 receipts/traces; L2 total fees still open |
| Story Aeneid | Full quote suite not completed | Not completed | Current CRL checks: 3 PASS / 4 explicit SKIP; historical state unavailable |
| Other registry networks | Initial read-only inventory only | Not completed | Not completed |

The RISC Zero SGX Mac return was received and verified on September 13. RISC Zero
TDX and Google V5 completed locally on September 14; SP1 V5 also completed locally
after correcting the runner parameters described below. September 14 additionally closes SDK
collateral acquisition/native input parity, actual deployment-script guards,
transaction-deployed runtime/configuration readback and the bounded raw
legacy/V2 gas/rollback comparison described below. The final reconciliation
passes for **63** selected deployment/SDK transactions, **29** comparison
transactions / **15** cold/warm pairs and **six** negative runs (**66** rejection
transactions, not 66 unique scenarios). The final runtime/configuration readback
passes with V2 restored to paused. Release signoff and historical legacy/ATKJ
applicability remain distinct gaps. Story historical/archive RPC belongs
to the separately requested focused CRL regression, not another full E2E.
Retired/mismatched registry chains need a decision only if selected for rollout;
they do not block the Sepolia E2E. None of these outstanding items is marked passed.

## Proof preparation

### SP1 V5 Mac return — September 14

**Correction discovered during actual Groth16 generation:** the earlier runner
incorrectly exported the global `FRI_QUERIES=100` override. This was an error in
the supplied acceptance/handoff scripts, not in the user's quote or guest.
SP1 5.2.2's official configuration uses core/inner **100** queries with blowup
log 1, shrink **50** with log 2, and outer **25** with log 4. A global override
changes all three. Earlier statements that this override left every circuit/FRI
parameter unchanged were incorrect. The Mac outer is valid under that overridden
configuration, **not compatible with the existing official Groth16 setup**.
Retain its archive for diagnosis; do not reuse or reissue the old handoff package
for release acceptance. No replacement trusted setup or guest rebuild is needed.

The user returned `sp1-v5-outer-result.tar.gz`; archive SHA-256:
`2f1f06796ac842f792950522207595e2c3523546199f8f940b5bdfd24fc97a29`.
Extraction into a fresh directory, recorded file checksums and byte comparison
of the compressed proof against the original local checkpoint pass. macOS
AppleDouble metadata is not used as input. The returned outer SHA-256 is
`b593d60ad867cccaf859255aac3e4e8af4c4e75cd384c6812c4642f420bf093b`.
The reported fixed Ubuntu ARM64 runtime and canonical SP1 program ID match the
handoff. The Mac runner records exit 0, **07:48:52–08:06:58 UTC / 18:06**, with
**97** Docker resource samples and a maximum observed **11.22 GiB** (sampled
container working memory, not an exact kernel peak). Its compressed/full
937-byte journal and BN254 wrap checks pass; no Groth16 was run on the Mac.

On receipt, local independent checkpoint verification, final Groth16 and the
last Sepolia E2E cell were still required. The original helper, host lock, canonical guest and
frozen input hashes still match. All seven official v5.0.0 circuit/setup files
were rehashed against the recorded download manifest and match. A serial local
continuation waits for sufficient available memory without stopping competing
work, retains the resource watchdog and rederives the expected wrap key before
accepting the returned checkpoint. Only verified EVM output can enter the fork
and Go/Rust SDK tests; the Mac log is not used as a substitute for that gate.

The first local run independently verifies the overridden outer at **08:41:55**,
then is stopped during gnark by the availability guard (**10:20.52** total,
max child RSS **3,714,804 KiB**). A standalone retry from its retained witness
exposes the functional incompatibility: **`invalid witness size, got 89111,
expected 24235`**. The original VK/PK/circuit hashes all match the official
v5.0.0 bundle; generating another setup would hide the actual runner error.

The three SP1 host helpers now require `FRI_QUERIES` to be entirely unset, and
the Mac runner no longer forwards an override. All three reject overrides of
`100`, `50`, `1`, and an empty value before reading inputs (**12 checks PASS**).
The corrected helper verifies the original compressed proof under official
defaults with the same program ID and **937-byte** expected journal. Therefore
core/recursive compression can be reused; only shrink/outer and subsequent
Groth16 must be regenerated. The corrected outer passes locally in **8:31.12**,
maximum child RSS **5,980,200 KiB**, with two Rayon threads. Its SHA-256 is
`fd782eb7370c029fbfce99ce0b25e032f3f779bf1d8f15acd977602fd26303cf`.
It uses the original canonical guest/input and reverified compressed proof;
all FRI defaults are retained. The obsolete Mac outer is rejected under official
defaults at **09:09:35 UTC** with `FriError(InvalidProofShape)`, before any
Groth16 invocation or verified outer export.
The standalone gnark runner and strict native importer additionally allow final
proving and SDK cryptographic verification to run in separate processes. The
importer's malformed transport regression rejects and writes no output.

Final official Groth16 generation **passes at 09:19:57 UTC** (93 seconds
including container startup; proving about 76.54 seconds). The official ARM64
image and existing v5.0.0 setup are unchanged. `GOMAXPROCS=1`, `GOGC=50` and a
soft `GOMEMLIMIT=8GiB` reduce transient memory; the sampled Docker maximum is
**8.787 GiB**, with an 11 GiB hard cap and the availability guard retained.
These runtime controls do not change proof parameters. The canonical witness
has the expected **24,235** elements; the obsolete witness is now rejected by
the runner's layout preflight before allocating proving memory.

The strict native import passes at **09:20:54 UTC**: original compressed proof,
canonical program ID, complete **937-byte** journal, Groth16 public input binding,
modified journal/wrong key/modified raw proof rejection and a final positive
control. The mutated curve point causes the upstream verifier subprocess to
report `invalid point: subgroup check failed`; that is the intended rejection,
not a failed positive control. The resulting **260-byte** EVM proof uses the
existing `a4594c59` route. Its immutable EVM JSON SHA-256 is
`edf9fdc7c924dcac3c76142d353a2d86c8224990e0fb264e99781144ef08e71f`.

The SP1 V5 full Sepolia suite passes **16/16, 0 failures, 0 skips**. Go and Rust
each pass explicit/default local transactions, at **467,555 / 669,543** receipt
gas, plus exact output/event parity. Its 17-transaction negative run passes
(11 rejections, two positive controls, four administration transactions),
and restores its starting snapshot. Six-cell proof/SDK/gas reconciliation and
the final manifest readback pass; no further Mac action is needed.

### Earlier checkpoints (historical, superseded by the completed matrix above)

The following chronological entries preserve intermediate resource failures and
partial counts. Statements about pending proof cells describe those earlier
checkpoints, not the current status. The early SP1 outer attempts also inherited
the erroneous global FRI override; their earlier "unchanged FRI" interpretation
is superseded by the correction above.

### September 14 serial run and additional acceptance

- RISC Zero TDX V4 composite: **PASS**, **02:18:28–03:21:45 UTC**, measured
  wall time **1:03:16**, maximum child RSS **3,648,260 KiB**. The frozen 4,935-byte
  quote/input and canonical Docker program produce the exact **873-byte** native
  journal; receipt cryptography, modified journal, wrong ImageID and modified
  seal rejection all pass. Succinct compression also passes in **33:17.85**,
  maximum child RSS **1,550,236 KiB**. Four Rayon threads, a 10 GiB virtual-memory ceiling
  and the process-family memory guard are enabled. No second prover runs concurrently.
- The pinned official ARM64 final-stage image
  `55236d558d1e16e27f86f73237215c49f686521cab7652931c61c96d62cabcfc`
  passes native final-stage proving for TDX V4, **03:56:03–03:56:38 UTC**.
  Independent cryptographic import, full **16/16** Sepolia suite and Go/Rust
  explicit/default transactions all pass. The **873-byte** journal and canonical
  ImageID are unchanged; the **260-byte** EVM proof uses `73c457ba`. EVM JSON
  SHA-256 is `ae55c77795d4a39c13db6a4c87d60083b1d428ee3aa7f35a964e27d810b76130`.
  Both SDKs use **490,484** explicit / **692,435** automatic receipt gas.
  No Mac action is required for this cell. The new
  `risc0-groth16-local.sh` bounds the container to 7 GiB, disables networking,
  mounts the input read-only and records resource samples. Mac fallback remains
  available but is not currently requested. RISC Zero Google V5 composite is
  **PASS**, **03:57:03–04:58:44 UTC**, measured wall time **1:01:41**, maximum
  child RSS **3,649,992 KiB**. The exact **937-byte** journal, receipt cryptography,
  modified-journal/seal and wrong-ImageID rejection all pass. Receipt SHA-256:
  `71e3ed84312ad4a2ec7dc8f0201596842ec5ed8658147583c4109454c92e8424`.
  Succinct compression passes in **32:44.92**, maximum child RSS
  **1,542,832 KiB**; witness preparation passes in **55.01 seconds**.
  Official native ARM64 Groth16, independent cryptographic import, the full
  **16/16** Sepolia suite and Go/Rust explicit/default transactions pass.
  EVM JSON SHA-256 is
  `746740ce842370954eb6635138ce8c2243547607be1ff415527717626a39d0ef`.
  Both SDKs use **492,548** explicit / **694,512** automatic receipt gas.
  SP1 V5 starts strictly after full RISC Zero V5 E2E success,
  with no concurrent prover. The SP1 runner can now stop after its verified BN254 outer checkpoint
  to release recursion allocations before gnark; this is not itself an EVM pass.
  SP1 V5 core proof is **PASS**, **05:33:15–05:44:50 UTC**, measured wall time
  **11:35.41**, maximum child RSS **7,422,300 KiB**. Full **937-byte** journal
  equality and modified-journal/wrong-vkey/modified-commitment rejection pass.
  Core SHA-256 is
  `ec3bab2ca7d5279a958e93811bf7ef0b3badf41716635ec7aa43004c11a2bb46`.
  Recursive compression passes in **41:32.09**, maximum child RSS
  **8,204,732 KiB**. Compressed proof SHA-256:
  `e0a8a149d21dcabf936858fdfc15940647e96753ab3fc43092586d16e1f88709`.
  Complete journal equality and compressed cryptography pass. BN254 outer
  encapsulation starts after that success; final Groth16/E2E remains open.
  The initial two-thread outer attempt was stopped by the resource watchdog
  after **15:16.64**, exit **143 / SIGTERM**, maximum child RSS
  **11,189,336 KiB**. Available system memory fell to **1,198,800 KiB**, below
  the 1.5 GiB guard. This is a resource failure, not a cryptographic rejection;
  no outer/Groth16 success is claimed. A new **single-thread** attempt resumes
  the verified compressed proof with unchanged guest/circuit/FRI parameters and
  the same guard. The successful core/compressed files are not overwritten.
  That single-thread attempt also reaches the memory guard after **29:05.35**,
  **06:44:49–07:13:54 UTC**, exit **143 / SIGTERM**, maximum child RSS
  **10,819,992 KiB**. The guard observes **1,497,728 KiB** available, below its
  1.5 GiB minimum. No prover is left running. This does not establish a quote,
  guest or cryptographic failure; outer/Groth16 and this last E2E cell remain
  unverified. The ignored `sp1-v5-outer-handoff.tar.gz` package contains the
  same verified compressed checkpoint, canonical program/input and Linux ARM64
  host helper, with source/lock/artifact hashes. `sp1-outer-container.sh` resumes
  only outer wrapping on the available Mac in a fixed, network-disabled Ubuntu
  ARM64 runtime; assign Docker 18 GiB, with a 14 GiB container limit. Its helper
  loading and fail-closed resource preflights are separate from successful
  outer proving. A returned checkpoint must be independently verified before
  local final Groth16, the 16-test suite, both SDKs and six-cell reconciliation.
  Handoff archive SHA-256 is
  `6b8ffd4273ba7c3b270531393e65bd444ca77054162ef4edcfcee6337e098929`
  (approximately 21 MiB). Its archive roundtrip/checksums, shell syntax and
  insufficient-memory failure/log-return checks pass. No final outer proof was
  generated by those preflights. The same-pin deployment readback also passes
  again at local block `0xb26012`; all five runtimes and expected configuration
  remain intact, and V2 is paused while waiting for the external checkpoint.
- A fresh **same-pin Sepolia** Anvil instance replayed 27 deployment/configuration/
  collateral transactions. The original PublicNode-backed process retained
  pruned-state failures even after `anvil_setRpcUrl`; a fresh process using
  `https://rpc.sepolia.ethpandaops.io` and `--no-storage-caching` resolved them.
  The pin/hash, release bytecode target and signed fixtures were not changed.
- Go acquisition: **6/6** V3/V4/V5 explicit/default evaluation cases. Rust:
  **12/12** direct and Multicall3-with-fallback, explicit/default cases; all
  generated inputs authenticate natively and match complete frozen journals.
  Rust independently verifies all six Go inputs. The acquired Go/Rust inputs
  are byte-identical. They are not byte-identical to every frozen input: some
  existing on-chain documents have August 24 issue dates / September 23 expiry,
  different valid signatures and FMSPC hex case. Frozen documents use September
  10/11 issue dates. Both authenticate at the frozen verification timestamp and
  have equal semantic collateral hashes/journals. No frozen input was replaced.
- This exposed and closes a Go V2 integration gap: the old proving helpers only
  generated the legacy binary envelope and queried quote-version-dependent
  collateral APIs. Additive `NewCollateralV2FromQuoteParser` and
  `GenerateInputV2` now select PCS API v4 / TCB Info v3 and the shared V2 ABI.
  They do not change the legacy remote prover/program defaults. Three offline
  fixtures match the frozen Rust ABI exactly; malformed/padded inputs and
  missing/wrong-version collateral reject. Seven relevant Go SDK packages pass
  their local regression tests; old remote portal/prover tests were not run.
- Full Foundry suite: **16 PASS, 0 FAIL, 0 SKIP**, including the actual staged
  `DeployDcapV2` script, stale expected-current helper guards, rollback and
  RISC Zero historical-route rejection. The two removed selectors
  `50bd1769/c101b42b` return `SelectorRemoved`; seven paused catalog routes return
  `EnforcedPause`, before proof decoding. These negatives are not valid legacy
  proofs. All 12 upstream RISC Zero catalog selectors were read back; arbitrary
  uncatalogued mapping entries are still not enumerable. The existing universal
  router and all its stored routes remain in place.
  All three authentic raw fixtures first pass with valid signed collateral and
  reject after advancing beyond collateral expiry. Actual real-proof tests also
  reject cross-backend use with the other backend's registered V2 ID. These are
  not synthetic signed quotes or a new journal maximum-age policy.
- Independent readback verifies all five deployed runtimes byte-for-byte outside
  compiler-declared immutable slots, and validates every immutable value/getter;
  all pass Paris target and EIP-170. Owner, fee basis points, all six Router
  components, all four new reader authorizations, evaluation 17–21 DAO mappings,
  legacy IDs/defaults and the exact V2 IDs pass. V2 remains paused. No Pico V2 ID
  or default was introduced. The compact
  [local manifest](dcap-v2-sepolia-local-manifest.json) records this readback;
  it is not a frozen release commit or permission to broadcast.
- Clean replay: Go/Rust each send six raw V3/V4/V5 and six existing real-ZK
  explicit/default transactions (RISC Zero SGX, SP1 SGX/TDX). Full output/events
  and SDK negatives pass. **51 selected deployment/SDK receipts and traces**
  reconcile without double-counting nested calls; SDK pause-admin transactions
  are outside this selected count. Intrinsic/calldata components and the data
  floor are now reported separately, without treating net gas as gross execution.
- Separate comparison: **26 local transactions PASS**, including a test-only
  two-call probe, three raw variants per fixture, pause/helper rollback/replay
  and the three available real-ZK cold/warm cases. The exact starting snapshot
  was restored. Cold/warm measurements occur within one transaction and include
  call/payment overhead; they are not standalone per-quote receipts.
- After TDX RISC Zero completion, **55 selected deployment/SDK receipts and
  traces** reconcile. ZK rows now derive quote version/body type and journal
  SHA-256 from confirmed calldata, so SGX/TDX cells cannot share an ambiguous
  backend-only label. SGX journals match across backends at 833 bytes; TDX V4
  journals match at 873 bytes. Another **17 RISC Zero TDX** positive/negative/admin
  transactions pass with exact snapshot restoration. The revised **16-test**
  full fork suite passes separately with each of the four completed proof cells.
  Offline Solidity V2 regression is **64 PASS, 0 FAIL, 0 SKIP**. Expanded Go V2
  tests reject outer/authentication/certificate length mismatches and missing
  certificates/CRLs for all three fixtures. A first sandboxed Go attempt failed
  on a read-only build cache; the authorized cache-enabled retry passed.
  The final four-proof comparison includes **27** transactions / **13** cold/warm
  pairs. Four transaction-negative runs (**68** control/rejection/admin
  transactions) pass with exact snapshot restoration. A compact report can be
  regenerated by `summarize-gas.mjs` without committing the full receipts/traces.
  Final offline native Rust regression is **35 PASS**; all seven reviewed Go SDK
  packages pass again. The new input encoder's single-worker, 60-second fuzz smoke
  run passes (**179 executions**); this is bounded smoke coverage, not exhaustive
  fuzzing. Guest core source and guest locks are unchanged from `81646e5`.
- A bounded real legacy SP1 proof was recovered from Sepolia transaction
  `0x77eb616e2eced89e1005f5df8f026b888ac96438c01ec2265bf9e795f1241db1`,
  block **9902908**. Its historical ID matches the migrated legacy default;
  existing-gateway cryptography and three tamper/wrong-ID negatives pass.
  Six current evaluation selections yield identical old-Fee/FeeV2-old-selector
  collateral reverts, not successful legacy attestations. The 797-byte journal
  is full TDX V4 output, **not ATKJ**. `legacy-sp1-replay.mjs` reproduces these
  read-only checks from the public transaction without committing bulk logs.
- Timestamp-policy regression explicitly distinguishes raw/current-block time
  from ZK/authenticated-journal time. An initial test incorrectly expected the
  unchanged proof to fail solely after current time advanced beyond collateral
  expiry; it failed that expectation. Inspection confirmed the agreed
  `WithTimestamp` behavior, so only the test expectation was corrected. RISC Zero
  TDX and all other completed cells now pass the full 16-test suite with the historical-proof acceptance
  regression. No contract or guest policy was changed. Native/guest mutations
  separately reject pre-/post-validity verification timestamps.
- After RISC Zero V5 completion, **59** selected deployment/SDK transactions,
  **28** comparison transactions / **14** cold/warm pairs, and **5** transaction
  negative runs pass. Positive ZK rows now include the proof hash, backend and
  program ID decoded from actual confirmed calldata; automatic IDs are read
  at the transaction's historical block. Negative runs also bind the exact proof
  hash. No proof cell is identified solely by a filename. All comparison/negative
  runs restore their exact starting snapshots.

| Raw quote, explicit evaluation | Deployed legacy Fee | FeeV2 old selector | FeeV2 V2 selector | V2 minus legacy |
| --- | ---: | ---: | ---: | ---: |
| SGX V3 | 4,896,198 | 4,899,785 | 5,144,791 | +248,593 (+5.08%) |
| TDX V4 | 4,118,757 | 4,110,841 | 4,347,249 | +228,492 (+5.55%) |
| Google V5 | 3,658,410 | 3,645,527 | 3,884,101 | +225,691 (+6.17%) |

These are actual same-pin local transaction gas measurements, not current market
prices or an all-network gas guarantee. Collateral ingestion remains separately
recorded from per-verification costs. Runners and commands are retained in
`scripts/fork-dcap-v2/README.md`; full local reports/proofs are not required in Git.

### Earlier completed proof stages

- Canonical guest source remains `81646e5754a8124d4a70a483882f11b515c98c7b`;
  guest source, guest locks and program identities have not changed.
- RISC Zero SGX V3 composite → succinct: **PASS**, 35:15.10 wall time,
  maximum child RSS 1,564,088 KiB. Both source and resulting receipts passed
  cryptographic verification, exact journal equality, modified-journal,
  wrong-image-ID and modified-seal rejection. This is still not an EVM proof.
- The unmodified `r0vm 3.0.3` generated the `identity_p254` witness for the final
  official Docker stage. Its Docker connection was deliberately disabled **after
  witness preparation**; the expected Docker failure is recorded as preparation,
  not proof success. No fake receipt is accepted.
- Mac handoff: local-only archive
  `docs/evidence/dcap-v2/fork-local/risc0-sgx-groth16-witness.tar.gz`, 734,203 bytes,
  SHA-256 `c5794787f98f1819204c7b0014f4eb343cc51f5752d0c21824bfcdc75e8b8fc0`.
  The archive contains input checksums and `risc0-groth16-mac.sh`; it is ignored
  by Git. Return the runner's `return.tar.gz` even on failure. Import the returned
  `proof.json` using `risc0_v2_groth16_handoff import` to verify against the original
  succinct claim and native program ID before exporting EVM bytes.
- **RISC Zero Mac return verified, September 13:** all ten returned checksums
  pass; `manifest.json`, `input.json` and `seal.r0` are byte-identical to the
  original local handoff. All archived result files match the supplied extracted
  files. `return.tar.gz` SHA-256:
  `ea77df24c2b4e4f294fb7e5bc00b45f55da27d8764081c34d441a5596fb9ed61`.
  The final Docker stage exited 0, **15:24:18–15:31:05 UTC (6:47)** on the Mac
  (Docker Desktop 4.90.0; 8,317,267,968 bytes allocated to its Linux VM). This is
  elapsed time, not a peak-memory measurement. `proof.json` SHA-256:
  `eb14ccef520c7f7f66e68972872b728be9e9cbd2242a3bef00d73dde1fa1ee01`.
  The importer independently verifies the source succinct receipt, reconstructs
  the original native-verified journal/claim, and verifies the returned Groth16
  proof with the pinned SDK parameters. Modified journal, wrong ImageID and
  modified seal all reject. The 833-byte journal is preserved; the EVM seal is
  260 bytes with existing selector `0x73c457ba`. Imported EVM JSON SHA-256:
  `8be95e09feab6fc9396ab0637cc5b8a8796b921f1ff5e6bd5d1fb34f67e2ab80`.
  Sepolia's fixed-block full Foundry suite then passes **13 / 13, zero skips**,
  including the actual reused RISC Zero universal verifier, FeeV2, real proof,
  wrong IDs/legacy ID, modified proof/journal/format, framing, evaluation, pause
  and Fee route freeze. This closes SGX V3 only, not RISC Zero TDX/V5.

The returned RISC Zero `image.txt` records a multi-platform **index**, explaining
its empty `platform=/` field. Independent official registry inspection verifies
index SHA-256 `a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee`,
with Linux AMD64 child `7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331`
and Linux ARM64 child `55236d558d1e16e27f86f73237215c49f686521cab7652931c61c96d62cabcfc`.
The handoff runner explicitly requests AMD64. The earlier blanket statement that
this final-stage image is x86-only is corrected: the pinned SDK source comment
says x86, but this observed index advertises both platforms. **ARM64 final-stage
proof compatibility now passes for TDX V4 through independent cryptography and
the existing Sepolia verifier**.
Returned evidence is preserved unchanged; no guest/lock/setup update is involved.

### Fresh RISC Zero SDK / transaction replay (September 13)

The previous local nodes had exited. A new Anvil 1.5.1 instance was started at
the **same Sepolia block 11689923 / hash recorded below**, with Osaka execution
and unchanged Paris contract artifacts. The first ethpandaops startup timed out
before a local node existed; the dependent deployment call therefore created
no transactions. Retrying against the existing PublicNode endpoint succeeded.
Both failure logs are retained rather than counted as test passes.

The fresh replay completed 27 deployment/configuration/collateral transactions,
six raw transactions per SDK (SGX V3 / TDX V4 / Google V5; both overloads) and
two real RISC Zero SGX proof transactions per SDK. **The selected 43 receipts and
call traces reconcile**; SDK administrative pause/restore transactions are not
included in this positive table. Go raw took 169.58 seconds while the new node populated its
remote state cache; it completed without changing the test deadline or pin.
Both SDKs pass explicit ID, default-ID lookup, automatic overload, exact journal
and events, altered proof/journal and wrong-ID rejection. Rust raw/native parity
uses each actual transaction block's timestamp. The frozen SGX native, RISC Zero
and SP1 journals also compare byte-for-byte at the identical original timestamp.

| RISC Zero SGX SDK transaction | Go receipt gas | Rust receipt gas |
| --- | ---: | ---: |
| Explicit program ID / evaluation | 492,092 | 492,092 |
| Automatic overload | 694,055 | 694,055 |

An additional 17 locally impersonated transactions cover two positive controls,
11 raw/RISC Zero rejection cases and four pause/freeze configuration operations.
All checks pass, including no accepted event for either reverts or returned
`success=false`. Altered RISC Zero proof/journal cost 1,855,535 / 302,586 receipt
gas under the explicit 2,000,000 ZK gas cap; these are not worst-case bounds.
The exact pre-negative-test snapshot/block hash was restored after saving the
receipts/traces. Only those 17 temporary transactions were removed from the
local node; the selected 43 positive transaction records remain. Final independent
`zkV2Paused()` readback is **true**. This test reset is not a production unfreeze.
No live network transaction, registry/default update or Git commit occurred.

### SP1 proof preparation (September 12)

- SP1 SGX V3 core → compressed: first attempt (16:44:46–16:58:06 UTC) stopped
  safely at the configured 8 GiB RSS threshold, not on a proof-verification error.
  Retry ran 17:03:53–17:45:31 UTC and **PASSED** cryptographic verification and
  exact journal comparison: 41:37.96 wall time, max RSS 8,149,544 KiB, no swap.
  It bounds checkpoints to one, uses rendezvous trace buffering and two Rayon
  threads. The existing verified core proof, SDK/prover/stark 5.2.2 and default
  circuit/FRI/VK checks are unchanged. An 11 GiB process-family RSS / 1.5 GiB
  available-memory polling guard protects the host; there is no proof timeout.
  Shrink and BN254 wrapping also pass. The final gnark run initially failed on
  a read-only witness permission mismatch (fixed by running as the host UID/GID),
  then hit a confirmed Docker OOM at the 9 GiB cap. Neither is recorded as a
  cryptographic failure. The verified BN254 checkpoint was reused, with its
  expected verifying key independently rederived from the pinned SDK.
  The 11 GiB-cap retry ran **18:05:30–18:08:38 UTC, PASS** (3:08.00 including key
  derivation; final Docker prove/verify approximately 49 seconds). SDK Groth16
  verification and exact 833-byte journal comparison pass. The host child RSS
  measurement excludes Docker and is not a combined peak-memory claim.
  The resulting 260-byte EVM proof uses the existing `0xa4594c59` route; no setup,
  circuit, program ID or guest changed. Sepolia real-proof acceptance now passes.
- Downloaded the existing official SP1 v5.0.0 Groth16 setup (3,025,985,400 bytes,
  SHA-256 `6cbc2c155c41001e81efd81119bd3d4f32313fcd3184df383d50225315b73104`).
  The hash pins this download, not an independent audit of the setup. No new
  trusted setup is generated; compatibility still requires a real proof accepted
  by the existing on-chain route.
- SP1 ATA TDX V4 core proof: **PASS**, 18:23:48–18:35:09 UTC,
  11:21.52 wall time, max RSS 8,014,864 KiB, no swap. The full 873-byte journal
  matches; modified journal, wrong key and altered proof commitment reject.
  Recursion verification passed at 19:14:58 UTC and BN254 wrapping passed at
  19:22:49 UTC. The final gnark stage triggered the 1.5 GiB available-memory
  protection at 19:23:22; this is a resource interruption, not a proof failure.
  Reusing the verified compressed/BN254 checkpoints in a fresh process completed
  **19:35:20–19:38:27 UTC, PASS** (3:07.25; final gnark prove/verify 48 seconds).
  No circuit/setup/guest change was made. The 260-byte v5 Groth16 EVM proof and
  exact 873-byte journal pass local SDK cryptography and Sepolia's existing
  universal verifier/FeeV2 acceptance, including the negative proof cases and
  both inherited universal-verifier freezes. The first narrow Forge invocation
  selected no tests; it is not counted as a pass. The corrected invocation ran
  one real-proof test, **1 passed / 0 failed / 0 skipped**.
  Go and Rust SDKs each pass both locally signed TDX proof transaction overloads,
  exact journal/events, wrong-ID and tampering rejection, with pause restored.
  Receipt gas is 465,490 explicit / 667,465 automatic in both SDKs. The EVM JSON
  SHA-256 is `c80daa3fb2d22b0cfef76cb2df11d687726ebefc0eb8aa5522a3ec115ad05004`.
  Hoodi also passes the real TDX proof plus FeeV2 rejection suite: **1 passed /
  0 failed / 0 skipped**, block **3611159**, timestamp **1789242228**, hash
  `0x40ea09199c6054a7730965d58bf00cad741509c6b0725aa7cf1e26b5b3ac3448`.
  This fresh pin is separate from the earlier Hoodi SGX/raw run, not a rewrite
  of that run's historical evidence.
  RISC Zero TDX and both V5 real-proof cells remain outstanding.

The official SP1 v5.0.0 gnark index includes ARM64 manifest
`sha256:7a7505bf609f3646cc058134bf016827af3af6a8d42f257fb77ac635448a8b65`.
Docker daemon pulls failed on GHCR connectivity; `crane v0.20.3` downloaded the
same immutable image. Archive SHA-256:
`24ecee2248e7110ca44eacc552aee26acada0326afbbc391754df23d03f5371e`.
Official config SHA-256:
`0c5055cd233e28d2827e1fdd43047a57e2a9b1ca9939cc497eb326239b76df88`.
Imported Docker image ID:
`sha256:ccb0c9a846f967999f737c672a2e4df9a6e6ddf194cc7e59cd94a0e4dae3a666`.
Import converted the manifest identity; runtime config and every rootfs layer
digest match the official config. Native ARM64 startup and the bounded
`prove --help` adapter pass, followed by the real Groth16 result described above.

The RISC Zero host V2 loader previously checked raw ELF magic, rejecting the
canonical combined user/kernel artifact. It now validates through the SDK's
`compute_image_id`. The canonical positive path and the malformed-program unit
test pass. Added host dependency edges reuse existing locked versions; no guest
dependency or circuit upgrade is involved.

## Observed network configuration

The [initial read-only snapshot](dcap-v2-fork-snapshot.json) covers 28 registry
networks and records partial reads and unreachable endpoints explicitly. It is
not a completed route/authorization/fee release manifest. Older deployed enum
ABIs can reject Pico queries; Pico remains local-only, not a production gate.

Sepolia pin: chain `11155111`, block `11689923`, hash
`0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096`,
timestamp `1789228656`. Confirmed existing routes:

| Backend | Reused universal verifier | Proof selector | Existing underlying verifier |
| --- | --- | --- | --- |
| RISC Zero | `0x925d8331ddc0a1f0d96e68cf073dfe1d92b69187` | `0x73c457ba` | `0x724d375B5b622e15f0E64e9Deb76a4cB17877797` |
| SP1 | `0x397a5f7f3dbd538f23de225b51f532c34448da9b` | `0xa4594c59` | `0x50ACFBEdecf4cbe350E1a86fC6f03a821772f1e5` (v5.0.0, unfrozen) |

SP1 v5 Plonk selector `0xd4e8ecd2` is not registered on this Sepolia gateway.
Sepolia legacy Fee `ZkRouteAdded` and `ZkRouteFrozen` genesis-to-pin queries both
returned empty arrays. Hoodi has SP1 v5 Groth16 route `0xa4594c59` →
`0x5A2823b1a5D55C5dD316F70b4cdB3B126fd561DE` (v5.0.0, unfrozen). Its full
route-event history and real-proof acceptance were incomplete at this initial
snapshot; subsequent results are recorded below.

Subsequent alternate-RPC reads at the tested pins successfully captured 37
Sepolia and 32 Hoodi contract records, each chain's 37 Router events, and no Fee
route override/freeze events in the genesis-to-pin response. Replaying the Router
events agrees with all captured versioned-DAO mappings (10 Sepolia / eight Hoodi
comparisons). Five / eight callers respectively appear in authorization events.
No restriction/configuration event was returned: the replay reports these as
unknown, not as an inferred false flag or constructor configuration. The local
compiled Router runtime hash differs from the deployed hash, so no unchecked
private-storage-layout equivalence is claimed. Direct fork behavior is tested
separately. The earlier public-RPC failures remain in the local record.

Sepolia's SP1 gateway history and all six event-discovered routes reconcile with
their pinned address/freeze readback, version and verifier hash. This does not
mean six proof formats were tested: the actual new proof above uses v5 Groth16
only. RISC Zero's router implementation has a non-enumerable selector mapping
without add/remove events; full historical discovery cannot be inferred from
an empty event response. The known v3 selector was read directly as noted above.
Sepolia's existing SP1 freezes at `0x09069090` (v3.0.0) and `0x2b4aeaf7`
(one v6.1.0 route) were also exercised without modifying the gateway: direct
calls reject with the exact `RouteIsFrozen(bytes4)` error and FeeV2 rejects
through the same gateway. The full suite remains **13/13 passed**. The presence
of existing v6 routes does not upgrade our SP1 v5 SDK or expand accepted V2 formats.

The initial Automata 65536 RPC reports that the chain is retired; 1398243 is
unreachable. The registered Tempo 42429 endpoint reports chain 42431. These are
coverage/scope gaps, not permission to change registry entries or switch chains.
Some other public RPCs were unreachable or rate-limited. Hoodi's original pin
was pruned by both tested public nodes; fresh-pin retries are tracked separately.

## Fork functionality

### OP Sepolia raw deployment / SDK rehearsal

The official OP Sepolia configuration activates Karst at `1781712001`. Installed
Anvil 1.5.1 rejects `--hardfork karst`; simulating the current chain as Ethereum
Osaka or older OP Jovian would not establish faithful L2 gas/behavior.
Official registry source observed at commit
`3a42979b691693934c8637e62836ecf9347eba36`:
[OP Sepolia configuration](https://github.com/ethereum-optimism/superchain-registry/blob/3a42979b691693934c8637e62836ecf9347eba36/superchain/configs/sepolia/op.toml).

Downloaded official **Foundry 1.8.1** ARM64 release, archive SHA-256
`27a32bd282d73018ab4d043de15ab0320b561c71b4bf3a549b130a0806e79f5c`,
and extracted only Anvil into a task-local temporary directory. Binary SHA-256
`1815e4dc42ea51a89adb69e68981d22ccd0f7d5c185d6373f7a813ad5f31871b`,
build commit `982849d3140c01fd3b72905759581a132df7aa98`. The normal installed
Forge/Cast/Anvil and all zkVM tools remain unchanged; release artifacts still use
the same solc 0.8.27 Paris settings.

The new local node confirms `network=optimism`, `hardFork=Karst`, chain **11155420**,
block **48718178**, timestamp **1789238896**, hash
`0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c`.
Neither RISC Zero nor SP1 has a registered default/ID at this pin; this remains a
**raw-only** rehearsal, with no backend expansion. Its standard evaluation-number
collateral was expired. Fresh public Intel-signed evaluation data was supplied
only to the local fork; its standard selection remains 20 (early list includes 22).
SGX JSON SHA-256 `b05097220853275196ca37be773161508d41affbc71f12e86d756ac32b4b9411`,
TDX JSON SHA-256 `fe66ad5c6bcad63e6f9f40fe76cfd4a7039103c8abca7239820d2530492ff54c`.
Both signed evaluation upserts passed the actual DAO validation (1,397,562 /
1,397,825 receipt gas). Full Fee/Router event requests hit provider range limits;
that inventory remains partial.

The initial attempts exposed two test-runner omissions: nested signed-JSON tuple
encoding and the evaluation DAO's required `ATTESTER_ROLE` (owner alone does not
authorize an upsert). The recipe now preserves exact JSON bytes and grants the
role through the actual DAO owner on the local fork. Failed-attempt receipts/logs
were retained and each retry started from the same fresh pin. No contract access
check, signature check, ledger timestamp or underlying DAO was replaced.

The final replay completed **48 successful deployment/configuration/collateral
transactions**, including all three FMSPCs' async upload/finalization, signed
SGX/TDX QE renewal and both evaluation renewals. Go and Rust raw acceptance then
passed SGX V3, TDX V4 and Google V5: explicit/default calls, native journal parity
(Rust), three rejection cases per fixture, six signed transactions per SDK, and
exact 2.1 events. All **60 receipt/call-tree gas records reconcile**. Raw receipt
gas matches the Ethereum Sepolia table below. The OP node returns no `l1*` or
`operator*` receipt fields: these are **execution-gas results only**, not evidence
that L1 data or operator fees are zero. Full OP migration/rollback, historical
route inventory and total L2 fee accounting remain open.

### Ethereum forks

The September 12 `DcapV2ForkTest` run on Sepolia passed **13 tests, 0 failures,
0 skips**, including the real SP1 SGX Groth16 proof. Subsequent SP1 TDX and
September 13 RISC Zero SGX results are recorded above; none supplies a real V5
proof. Hoodi initially passed **8, failed 0, skipped 1** including legacy
coexistence/rollback: chain
`560048`, block `3610391`, timestamp `1789232112`, hash
`0xc2cefaa79e3f2a323d34e98e15212904885113a1cee4b4be90a29a6104e0ad1a`.
The original Hoodi pin was pruned; no failing historical read is counted as a
contract failure or as a successful test.

Hoodi's expanded suite subsequently hit pruning on previously uncached slots:
9 passed, 3 RPC/database failures, 1 skipped. The full suite was then rerun at
block **3610600**, timestamp **1789234860**, hash
`0xa3dd061cb1f7fdf67fc4ac39526f0ba9267b680cfc37eee93c4209f31cd8c77e`:
**12 passed, 0 failed, 1 explicit real-proof skip**. Earlier missing reads are
not counted as successful tests. The first real-proof run at that pin later
encountered a pruned SP1 gateway slot (12 pass, one RPC/database failure).
The complete suite then passed **13/13, no failures or skips** using
`https://rpc.hoodi.ethpandaops.io`, block **3610775**, timestamp **1789237116**,
hash `0x8d68efc5b1c2894f95b9296effa693fbe21f703d006b2fe6b381987875bd4fb7`.
This includes the real SP1 SGX Groth16 proof and the same nine rejection checks
as Sepolia. The failed historical read remains recorded, not counted as a pass.

Ethereum mainnet fork: chain **1**, block **25962960**, timestamp **1789235675**,
hash `0xd117b72b4584cdd9559465b7fda232f449063d1ad0dc6c7c8c82b08f5de87fb2`:
**12 passed, 0 failed, 1 explicit real-proof skip**. All three raw fixtures,
legacy coexistence, deployment/configuration, helper rollback and fee checks pass.
This is a local fork result, not a mainnet transaction or a new backend deployment.
Its async DAO needed separate upload plans for all three FMSPC/TEE pairs.

The first mainnet preparation incorrectly treated a matching QE body hash as
proof of cache validity. The chain held an older, expired validity interval with
the same body hash. The harness now reads both FMSPC/QE validity intervals and
performs the real signed upsert when needed. It does not warp the block clock,
replace a DAO or bypass rollback protection. The Sepolia transaction runner also
checks validity, and explicitly fails if its pinned QE snapshot requires renewal.

- Deploy helper, FeeV2 and V3/V4/V5; copy existing legacy/default IDs and fee BP,
  register canonical V2 IDs only for already configured backends; keep ZK V2 paused.
- Authorize four new Router readers, switch only PCKHelper, verify five other
  Router addresses unchanged; exercise wrong-owner, pause/unpause and helper rollback.
- Authentic SGX V3 / TDX V4 / Google V5 outputs match entire frozen journals with
  only the verification timestamp updated to the actual fork timestamp.
- Positive V2 events have explicit 2.1 topics and matching backend/output bytes.
  Mutated signatures and trailing data reject without accepted events. Invalid
  evaluation and missing authorization reject; reauthorization restores success.
  The authorization negative explicitly enables restricted-reader mode because
  public-reader mode is a valid live Router setting.
- Google V5 needed the **existing async FMSPC DAO** protocol, not the old sync
  selector. Payloads are generated by a hash-checked mechanical extraction of the
  QPL encoder at `e110b001ac7af69b1cbf2d51293d29a404d5b983`. Its real upload,
  finalization, Intel signature validation and resulting content hash pass.
- Deployed legacy Fee and FeeV2's old selector produce identical outputs before
  and after the helper switch for all three quotes. On helper rollback, both
  legacy paths remain available and V2 raw rejects; rolling forward restores V2.
- Sepolia additionally passes the exact original 8,000-byte TDX rejection,
  attribute/signature mutations, nonzero fee collection, insufficient payment,
  excess refund, unauthorized withdrawal rejection and authorized withdrawal.
  Fee settings are restored. Mutated debug bits fail signature verification
  before policy: they are **not authenticated debug-policy coverage**. The real
  historical Alibaba V5 input returns `TCBR` on the Sepolia pin before the
  migration-service check. On the new Hoodi pin it reaches and rejects with
  the exact `TDX migration service TD measurement is not zero` policy error.
  The test asserts either of these explicit rejections and records which occurred;
  only the Hoodi result supplies this authenticated policy-specific coverage.

The `fork_osaka` profile uses Osaka execution/precompiles but restricts compilation
to the release Paris settings. Simply calling `setEvmVersion` did not initialize
P-256 in this Foundry version. No P-256 mock/shim is used by the Sepolia V2 suite.
The default release profile is unchanged. Solidity remains 0.8.27, via-IR, 200 runs.

Story 1315, block 23533855: **3 passed, 4 explicit skips**. Current signed CRL
upsert/index, legacy stored-CRL migration and expired-CRL rejection pass. Fresh
Intel CRL SHA-256 is `acc907f160a59adeb5a8381787d9f6d6d41d7cdb39583e075ee0a2eda069322a`,
valid 2026-09-12 15:57:24 to 2026-10-12 15:57:24 UTC. This legacy Story harness
uses the deployed P-256 software shim locally; its gas is not native-precompile gas.

The three July 57/129 transition/reissue tests initially failed expiry checks.
A diagnostic clock warp then correctly failed against newer stored collateral
or its validity window. **No warp or anti-rollback bypass is retained.** They
require a genuine historical fork with matching ledger state, and are explicitly
skipped outside the fixture window. The optional legacy quote replay also lacks
its required quote/collateral setup. These four gaps remain open.

A genuine matching historical block was located: **20963911**, timestamp
**1784202300**, hash
`0x9c53490d13bad96a5a13e86f4c5e007032e77e99a26b7a04f0fe78da160c4310`.
The public Story RPC returns its header but not its account/storage state
(`historical state ... is not available`). The three historical tests therefore
fail in fork setup, not in CRL validation. An archive RPC for this block is
required; the user has been asked. This gap cannot be closed with a time warp.

## Earlier cost measurements (September 12–13)

Sepolia Paris-bytecode internal-call measurements (not full transaction gas):
raw SGX V3 4,785,047; TDX V4 3,984,840; TDX V5 3,044,450. These exclude transaction
intrinsic/calldata costs and must not be presented as final user gas quotes.
V5 FMSPC async calls: start 389,500; basic 985,007; batches 4,145,956 / 2,031,402 /
1,765,538; finalize 686,253. Harness parsing/assertions are not deployment costs.

The localhost-only Anvil runner completed **27 successful deployment,
configuration and collateral transactions** against the pinned Sepolia state.
It signs no production transaction and accepts no operator private key.
The updated freshness-aware recipe was also replayed from a second clean
Sepolia fork and completed all 27 bootstrap transactions, 12 Go/Rust raw and
four Go/Rust SP1 ZK transactions successfully. All 43 receipts/traces reconcile
again and raw/ZK receipt gas matches the first run. Public-RPC delays prolonged
the second Go raw run to 215 seconds, but it completed successfully.
New runtime sizes (Paris, via-IR, 200 runs) are below EIP-170: PCKHelper 13,898;
FeeV2 22,306; V3 19,764; V4 23,129; V5 23,972 bytes.

| Actual Anvil transaction | Receipt gas used |
| --- | ---: |
| Deploy PCKHelper | 3,057,887 |
| Deploy FeeV2 | 4,899,717 |
| Deploy V3 / V4 / V5 | 4,323,087 / 5,049,941 / 5,232,853 |
| Go/Rust SDK raw SGX V3 explicit / default | 5,144,791 / 5,400,231 |
| Go/Rust SDK raw TDX V4 explicit / default | 4,347,249 / 4,602,685 |
| Go/Rust SDK raw TDX V5 explicit / default | 3,884,101 / 4,139,547 |
| Go/Rust SDK SP1 Groth16 SGX explicit / default | 467,098 / 669,085 |

Go and Rust SDKs: all three fixtures passed explicit/default `eth_call`, modified
quote, trailing data and invalid evaluation rejection, followed by **six real
locally signed transactions per SDK** (both overloads) and exact 2.1 event/output
checks. Rust recomputes native DCAP output at each actual transaction block's
timestamp. Explicit/default gas matches between SDKs. Go has a public explicit
raw transaction helper; its default transaction test uses the SDK's embedded ABI
binding, not a nonexistent convenience API.

Both SDKs also pass the real SP1 SGX Groth16 path: explicit ID, SDK default-ID
lookup, automatic overload, modified proof/journal and wrong-ID rejection, plus
**two locally signed ZK transactions per SDK** and exact 2.1 event/journal parity.
The transaction tests use the existing SDK bindings; they do not add fictitious
convenience APIs. They unpause only the local FeeV2 and verify that its original
paused setting is restored before writing a passing report. SP1 TDX V4 SDK proof
transactions also pass as recorded above. The September 13 fresh replay adds
RISC Zero SGX SDK proof success. RISC Zero TDX and full SDK collateral acquisition
subsequently passed on September 14, as recorded above. Both V5 proof cells
remain open. Registry promotion to live V2 addresses is a later approved release action.

The Sepolia Foundry real-proof test additionally rejects altered output major,
legacy program ID, truncated proof, invalid evaluation, pause and frozen route.
Its aggregate test-method gas includes nine negative checks and is **not** the
positive transaction gas. No universal verifier mock is used.

The second isolated node additionally completed **17 gas-measured transactions**:
two positive controls, 11 raw/ZK rejection cases and four pause/freeze configuration
transactions. Actual receipt/trace results distinguish a reverted transaction
from a successful transaction returning `success=false`; neither may emit an
accepted event for a rejection. The exact pre-test local snapshot was restored
and its block hash checked. Only these temporary test transactions were removed
from that node; their receipts/traces remain in the ignored local report. This
test reset is not a production unfreeze/rollback mechanism.

| Rejection transaction | Receipt gas | Receipt outcome |
| --- | ---: | --- |
| Raw trailing data | 194,220 | Returned false |
| Raw signed-body mutation | 2,758,493 | Reverted |
| Raw truncated header | 32,431 | Returned false |
| SP1 altered proof | 1,883,003 | Reverted |
| SP1 altered journal | 277,722 | Reverted |
| Unsupported output major | 55,770 | Reverted |
| Wrong V2 program ID | 55,770 | Returned false |
| Truncated proof | 46,045 | Returned false |
| Invalid evaluation | 291,967 | Reverted |
| V2 paused | 55,770 | Returned false |
| FeeV2 route frozen | 55,770 | Reverted |

Raw negatives used a 12,000,000 gas limit, ZK negatives 2,000,000. In particular,
invalid curve-point/precompile failure gas depends on the supplied cap; these
are measured transactions, not universal worst-case gas bounds.

The selected **43 transaction receipts and call traces reconcile** (27 bootstrap,
12 Go/Rust raw and four Go/Rust SP1 ZK transactions). The gas recipe assigns
each node its inclusive gas minus direct children's gas, so buckets do not double
count nested calls. The root residual includes transaction accounting and
entrypoint work; it is not pure Solidity cost or pure intrinsic gas. Refund/floor
contributions, cold/warm/legacy comparisons, L2 data fees and other real-proof
cells are not yet separately covered. Detailed local reports are regenerated with the
[runner recipes](../scripts/fork-dcap-v2/README.md), not committed as bulk evidence.

## Current remaining work

The September 14 six-cell V2 single-network acceptance is **complete**,
including both SDKs, collateral acquisition, fresh same-pin replay, deployment/
runtime/configuration readback, negative transactions, helper rollback and raw/ZK
gas reconciliation. Final release commit/artifact freeze and selected production
target configuration preflight remain **open**, as do the explicitly bounded
historical legacy-proof/ATKJ and Story archive-CRL follow-ups. No successful full
legacy/ATKJ proof replay is inferred from registration migration or V2 success.
Other-network full E2E and L2 total-fee completion are not gates for this phase.
The local FeeV2 ZK path was restored to paused after the recorded acceptance
runs. No live deployment or registry/default write occurred.
