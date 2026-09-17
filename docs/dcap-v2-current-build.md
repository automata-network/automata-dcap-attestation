# Current guest build handoff — 2026-09-17

Status: **RETURNED DOCKER A/B BUILDS AND GUEST REGRESSION PASS; RISC ZERO COMPOSITE PASS; SP1 CORE BLOCKED BY HOST MEMORY**.

## Verified return (2026-09-17)

Machine-readable candidate IDs/provenance: [current programs](dcap-v2-current-programs.json).
This is not a published network registry; verifier addresses/proof selectors
still require target-chain readback and actual proof-format verification.

Both returned archives match the frozen source archive, pinned official image /
AMD64 platform, local harness and guest lockfiles. Complete A/B program bytes,
recorded SHA-256 values and normalized native IDs match. Archive paths/types
were checked before extraction; AppleDouble metadata was ignored. These are new
minCheck/Keccak programs, not the historical 2026-09-11 candidates.

| Backend | Program SHA-256 | Native ID |
| --- | --- | --- |
| RISC Zero | `2934e1f685f521a38d5cfbfc7f25d9d634c612d1fbc1b277cef6b051b3c87dae` | `0x7b60cf33cc76f0e60d143c445a022e8a3b3915ce5fb51f1a3673e8a509238b1b` |
| SP1 | `5663ae20a40d9ebf521ac32c2e13ac6f3f83cf680d22f34d483b2354b89210f2` | `0x008a2b48b8290017e166630a5872c76383ad788e4a4aa3481a7d2c8c576a4d1a` |

RISC Zero program size is 1,862,448 bytes (complete SDK `guest.bin`, despite the
`.elf` suffix); SP1 ELF size is 1,777,324 bytes. Build evidence alone does not
approve registering these IDs or establish real-proof/on-chain acceptance.

```text
risc0.evidence.tar.gz SHA-256: 00531ce4ceb35c4dc4da5244f33c60bed9c00538096b25826cd80fdaf51d8673
risc0-session.log SHA-256: dc99adcc82a5fc9c2ba1570b3503e3c1b77e847d60ee7e652b53dc971e995ab7
sp1.evidence.tar.gz SHA-256: 35ed1f20fcfaae6911b01be2a5157bd6c3675ace97065470302e87c95c2be4c0
sp1-session.log SHA-256: 2fdcab57be93e2a182dc1118ce5ff99c03fc658e263b0661d7bb9acfdf8b5d30
```

Original archives/logs and validated extraction are retained locally under
`docs/evidence/dcap-v2/fork-local/2026-09-17-docker/` (ignored). Only the procedure
and compact result record belong in Git. No legacy embedded program, native
development artifact, published registry address or on-chain ID was overwritten.

Repeat evidence checking with `methods/docker/verify-returned.py BACKEND ARCHIVE
359def3bce58ba269c48373817f48b7144424f14 NEW_DIRECTORY` (path relative to
`rust-crates/libraries/zkvm`). It validates before extracting and never executes
scripts from the returned archive. Actual native IDs are independently recomputed
by the local guest execution runners, not trusted solely from archive text.

### Exact-program guest regression

Both native IDs above were independently recomputed by the local pinned SDKs.
Optimized host execution runners were rebuilt with `--release --locked --offline`
against the current source, without rebuilding the guest programs. Each returned
program passed all five offline fixtures (`v3`, `v4`, Google `v5`, `ata-sgx-v3`,
canonical/extracted `ata-tdx-v4`) with byte-identical expected journals: 10 positive
executions. Each backend rejected all eight SGX input mutations: 16 negative cases.
The 8,000-byte original TDX padding remains an invalid input, not a new success.

Solidity raw-path regression was also rerun: `PublicAtaSgxV3Test` (9),
`PublicAtaTdxV4Test` (10), and `QuoteV5PublicFixtureV2Test` (3), **22/22 PASS**.
These independently validate the same frozen journals/events and negative cases
against the current Solidity implementation. This is offline regression, not a
live Hoodi deployment or acceptance of a newly generated ZK proof on-chain.

The first debug-host run was deliberately stopped to use optimized host runners;
its partial logs are retained in `execution-results-debug-partial`. The complete
authoritative run is `execution-results`, with `PASS.txt`. No guest, cryptographic
parameter or expected journal was changed to speed up the host runner.

Repeat: build `v2_fixture`, export the five fixtures into `inputs/`; build
`risc0_v2_execute` / `sp1_v2_execute` with their respective features, `--release
--locked --offline --target-dir rust-crates/target`; run
`bash scripts/deploy-dcap-v2/verify-current-guests.sh VERIFIED_BUILD_DIRECTORY`.
The runner requires fresh result paths and verifies the archived artifact hash.
The archive-validation script also passed eight independent unsafe/incomplete
archive rejection tests (`python3 -B .../docker/test-returned.py`).

### Real proof continuation

The current returned RISC Zero program generated a real **SGX V3 composite
receipt**. Receipt cryptographic verification, the full 833-byte journal,
modified journal / wrong image ID / modified seal rejection, and independent
file readback all passed. Proving and initial checks took **1:02:58**, with
maximum process RSS **3,694,716 KiB**. Proof SHA-256:
`49f2177aceb5706070894d348b66f44749af1981f28dcd37b766a4d757bebee7`.
SP1 SGX V3 was started only after RISC Zero finished. The first attempt
(`sp1-ata-sgx-v3-proof`, shard size 262144) was terminated by the resource guard
after 7:26.70: host available memory reached 1,538,632 KiB, below the 1.5-GiB
headroom threshold. Exit code was 143, with no complete proof. This is a
resource stop, not a cryptographic failure or pass. GNU `time` also reports the
terminating signal; its trailing `Exit status: 0` is not a successful proof.
The wrapper's `exit.txt` and absence of `PASS.txt` are authoritative.

The host-only SP1 helper now permits SDK-supported smaller execution shards via
`DCAP_SP1_SHARD_SIZE` (65536, 131072, or the unchanged default 262144). This does
not change the guest, vkey, FRI security parameters or VK/shape checks. Parsing
tests cover accepted sizes and rejection of invalid/larger values (2/2 PASS).
Retry logs are kept separately; the shard-131072 attempt uses:

```sh
DCAP_SP1_SHARD_SIZE=131072 bash scripts/deploy-dcap-v2/prove-current.sh \
  sp1 docs/evidence/dcap-v2/fork-local/2026-09-17-docker ata-sgx-v3 shard17
```

That retry also stopped at a later memory peak, after **13:14.29**, with
1,411,244 KiB available at the guard sample (exit 143, no complete proof).
It reached trace index 120, beyond the first attempt's index 41; reducing CPU
shards alone did not fit the final workload into this busy host's free memory.
Neither stopped attempt establishes SP1 proof validity. Both logs are retained.
All proving processes have exited; no local background proof remains.

The [SP1 core handoff](../scripts/deploy-dcap-v2/sp1-core-handoff.md) uses the
same returned ELF/input and the rebuilt ARM64 helper in a pinned offline runtime.
It requires an otherwise idle Mac with at least 16 GiB assigned to Docker and
caps the proof container at 10 GiB. This is host execution, not a replacement
for the official paired Docker guest builds. The helper load/usage preflight
passed in that exact runtime. The wrapper's six mocked control-flow tests cover
existing results, corrupted inputs, platform/memory refusal, and returning
success/failure logs (6/6 PASS); they are not real-proof tests. The Mac proof
remains NOT_RUN.

Prepared local bundle:

```text
docs/evidence/dcap-v2/fork-local/2026-09-17-docker/sp1-current-core-handoff.tar.gz
SHA-256: cf9db9b0a73ae7d3fee6b25e2f6db1365ac5e532002b8874456d15c34eb059a8
```

Verify this hash before extraction. Follow the included README and return
`sp1-current-core-result/return.tar.gz`, including on failure. The package's
ten file checksums passed locally. It contains no private keys or RPC credentials.

These new IDs still have **no EVM-format proof acceptance**; historical proofs
do not cover them.

`scripts/deploy-dcap-v2/prove-current.sh BACKEND VERIFIED_BUILD_DIRECTORY FIXTURE [ATTEMPT_LABEL]`
runs the rebuilt release proof helper with no fixed time limit, then independently
reloads/cryptographically verifies the result. Native ID, full journal, wrong-ID,
modified-journal and modified-proof rejection checks are mandatory. It records
input/runner/proof hashes, exit code, timing and sampled memory. Backends are run
serially with the existing 8-GiB RSS / 1.5-GiB free-memory guard; the guard may stop
only this proof family, never unrelated work. Circuit/FRI/VK checks remain enabled.
These core/composite stages are not EVM proof compression or live Hoodi acceptance.

The handoff instructions below describe the completed transfer and remain the
repeat procedure.

Local checks for this handoff/deployment revision: 25 Solidity tests passed
(isolated deployment, legacy rollout, FeeV2 and minCheck), 7 mocked publisher
tests passed, 14 Rust registry tests passed, and the Go registry suite passed.
The broader Go godcap packages also compiled in the filtered registry run.
Docker harness checks passed (5 command guards + 7 fake-tool portability cases).
None of these results is a new Docker A/B build or real-proof acceptance.

Freeze guest source `359def3bce58ba269c48373817f48b7144424f14`, containing the
minCheck/Keccak revision and the reviewed PCCS gitlink. Subsequent deployment
script/registry changes do not modify the frozen guest inputs. Any later guest
or dependency change requires a new source freeze and handoff.

The official image/platform pins remain those in
[the Docker recipe](dcap-v2-container-rebuild.md#pinned-release-build-environments).
On this ARM64 worker the current SP1 image still fails even `/bin/true` with
`exec format error`. The RISC Zero pinned image is no longer installed locally;
no pull/emulation setup was performed. Use the previously working Mac/Rosetta
worker for both official paired builds. Do not replace them with host builds.

Prepared bundle (ignored local evidence, not a Git artifact):

```text
docs/evidence/dcap-v2/fork-local/2026-09-17-docker/dcap-official-handoff.tar.gz
bundle SHA-256: 745ebbcdbb3c029aef2600bc01388a249d376bf638805b188f5ec904cd48edb5
source.tar SHA-256: fb9d457dc225511d284f21139bd03d71b46c716f7caccb8c2ff1ab88e33af09c
RISC Zero guest Cargo.lock SHA-256: b1effad0065ea61600220be04a4610f260b8089aeec996bc3a8ffa5a0e80f190
SP1 guest Cargo.lock SHA-256: d7aadb020fc6f848e600eb423274c3701a9aa0fd24865aa087e5944258f7e20f
```

The bundle contains the exact committed source and separately hashed current
harness/README. It contains no .env, credentials, build caches or Solidity
submodule contents. Lockfiles are unchanged from the earlier build, but guest
semantics changed: **unchanged lock hashes do not make old IDs valid**.

## On the Mac

Copy the bundle to Downloads (or adjust the path) and use the already installed
pinned tools from the [handoff README](../rust-crates/libraries/zkvm/methods/docker/README.md).
Run the two backends serially:

```sh
shasum -a 256 "$HOME/Downloads/dcap-official-handoff.tar.gz"
# Must equal the bundle SHA-256 above before extraction.
DCAP_BUILD_WORK="$(mktemp -d "$HOME/dcap-v2-current.XXXXXX")"
tar -xzf "$HOME/Downloads/dcap-official-handoff.tar.gz" -C "$DCAP_BUILD_WORK"
cd "$DCAP_BUILD_WORK/dcap-official-handoff"
bash run-handoff.sh risc0
# Inspect success/failure, then run the second backend.
bash run-handoff.sh sp1
```

Return both generated `evidence.tar.gz` files, named by backend, and the new
`risc0-session.log` / `sp1-session.log`. Do not resend the 2026-09-11 archives.
Even on failure, return the archive/logs and retain the output directories.

## After return

1. Validate source/image/harness/lock hashes and complete A/B bytes/native IDs.
2. Execute the **returned programs** against the frozen SGX V3, canonical TDX V4,
   Google V5 and existing rejection fixtures; compare revised journals.
3. Generate real proofs with those same programs using the existing
   `risc0_v2_prove_local` / `sp1_v2_prove_local` examples and compression/Groth16
   workflows. Reverify outputs; never relabel old receipts/proofs as current.
4. Use the returned native IDs in the isolated deployment plan and FeeV2
   registration. Run actual on-chain tests with the new EVM-compatible proofs.

Core/composite proofs alone are not ready for an EVM universal verifier. Frozen
historical fixture timestamps are useful offline/fork tests; live Hoodi still
requires matching collateral present and valid under the corresponding selector's
rules. Do not upsert experimental collateral into shared production-user storage.
Pico remains local-only and is not added to Hoodi or other network registries.
