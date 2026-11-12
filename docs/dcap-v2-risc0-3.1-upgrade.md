# RISC Zero 3.1 security upgrade (V2 only)

## Boundary and pins

[GHSA-g6qg-9j8p-7j87](https://github.com/risc0/risc0/security/advisories/GHSA-g6qg-9j8p-7j87)
and the [Ethereum advisory](https://github.com/risc0/risc0-ethereum/security/advisories/GHSA-mm6c-35cm-g4x2)
invalidate the old circuit's trust boundary, not just the prover software.
Old receipts, succinct checkpoints and cached aggregation roots are **not**
migration inputs. Re-prove from the quote/collateral input.

| Component | Pin |
| --- | --- |
| `risc0-zkvm`, `r0vm`, `cargo-risczero` | `3.1.0` |
| `risc0-build` | `3.0.7` |
| `risc0-groth16` / binfmt / zkp | `3.0.6` |
| rv32im / recursion / keccak circuits | `4.1.0` |
| `risc0-ethereum-contracts` | `3.1.0` |
| Ethereum submodule | `ff30da77ba4afdd496290ebebedb205348b15d83` (`v3.1.0`) |
| Initial release allowlisted RISC Zero selector | `0xe71e6620` |
| Groth16 setup | `v2026-10-20.1`, AMD64 manifest `sha256:49093ed164b82aca9305dd80e4a6eb996bd443201ac7bd50b52909b2761ef583` |

The official guest compiler image remains Rust 1.88, pinned in
`methods/docker/reproduce-official.sh`; that is separate from the SDK/circuit
upgrade. Both strict and minimal programs require fresh paired Docker builds.
Do not assume their new native image IDs from old ELF hashes or registry entries.

The V2 entrypoint requires an explicit `addVerifyRoute(RiscZero, selector, verifier)`
entry. Unknown selectors return an unconfigured-verifier failure: RISC Zero never
falls back to the default verifier, even if its router supports that selector.
`freezeVerifyRoute` permanently disables a selector, including future re-registration.
Both overloads/modes share this boundary; SP1/Pico retain their existing fallback.
The owner can approve future audited circuits without redeploying DCAP. This release's
deployment scripts and SDK remain pinned to `0xe71e6620` / 3.1.0; future release pins
must be reviewed separately. Do not explicitly register vulnerable old circuits or
cached set-aggregation routes. A selector is a routing discriminator, not a
cryptographic trust anchor: its configured verifier must be trusted. The SDK rejects
V2 set aggregation and dev-mode proving, and cryptographically verifies every exported
V2 seal against the locally derived image ID and journal, for both Bonsai and Boundless.
Its seal selector is derived from the pinned SDK verifier parameters, not a separate
literal. Boundless also pins the local image ID before submitting the request.
For Bonsai, set `BONSAI_API_URL`/`BONSAI_API_KEY` before starting the process;
per-request overrides differing from the environment are rejected instead of being
silently ignored by the upstream environment-configured prover. No secret values
are included in that validation error. The Mac runner uses local proving only.
Raw quote verification, output/journal schema, contract ABI, SP1 and Pico are
unchanged. Historical V1.1 deployments are not migrated by this patch.

## Mac: fresh programs and proofs

Use the Apple Silicon Mac with Rosetta enabled in Docker Desktop. Allocate
16 GiB to Docker, retain enough free disk space for Rust builds and six proof
checkpoints, and run serially. This is CPU proving and may take hours. Nothing
below submits a transaction or requires a private key/API key.

Commit the complete patch first, then check out that exact commit on the Mac.
Do not use the pre-patch commit: the Docker builder exports committed source.

```bash
git submodule update --init --recursive
rzup install cargo-risczero 3.1.0
rzup install r0vm 3.1.0
rustup toolchain install 1.88.0 --profile minimal
rustup toolchain install 1.97.0 --profile minimal
cargo risczero --version
r0vm --version
rustc +risc0 --version
```

The first two version checks must report 3.1.0; `+risc0` must report 1.88.0.
Keep the already-installed RISC Zero 1.88 compiler selected. Python 3 and Docker
must be on PATH. Install/update `rzup` separately only if its component download
fails; do not silently substitute a different runtime version.

From the repository root (replace the output placeholder with a new directory):

```bash
export DCAP_PROOF_MEMORY=12g
bash scripts/fork-dcap-v2/risc0-v31-on-mac.sh \
  "$(git rev-parse HEAD)" /absolute/new/risc0-v31-result
```

The runner builds each mode twice in the pinned official Docker image, compares
program bytes/native IDs, and uses those exact artifacts for SGX V3, TDX V4 and
Google TDX V5 execution and Groth16 proving. It also runs the authenticated
Alibaba migration-service policy control. The final stage uses the pinned
AMD64 Docker setup through Rosetta. Returned proofs are imported and verified
with the 3.1 SDK, including wrong-ID, changed-journal and changed-seal controls.

Return **`risc0-v31-result/return.tar.gz`**, including on failure. Preserve the
whole local result directory: the archive omits large build trees, witnesses
and intermediate receipts; these can be reused to resume a failed stage.
Do not restart the entire run without inspecting the last failed stage.

### Docker export path failure before proving

`Duplicate platform result requested "linux/amd64"` followed by a
`risc0/build/src/lib.rs` missing-file panic after a successful Docker build is
caused by the wrapper adding a platform flag already supplied by the SDK.
BuildKit exports the raw `guest` / `guest-minimal` files under
`target/riscv32im-risc0-zkvm-elf/docker/linux_amd64/`, while the SDK expects them
directly in `docker/`. The wrapper now preserves either SDK flag spelling
(`--platform=linux/amd64` or `--platform linux/amd64`) without adding another.
The AMD64 default remains for callers that do not specify a platform.

For a run stopped at this first build, preserve the failed result directory,
commit/sync the wrapper fix, and rerun with the new source commit and a fresh
output directory. There are no proof checkpoints to resume at this stage.
Do not move raw guest files into place or reuse the bundled V1 guest binaries:
the successful SDK build must package the user/kernel binary and both clean
builds must pass the byte/native-ID comparison. `FromAsCasing` warnings alone
do not indicate this failure.

These fixtures have historical authenticated timestamps. They are regression
inputs, not a claim that collateral is current or that a live Hoodi transaction
will accept them today. No timestamp/signature is rewritten. After return,
validate the archive, then exercise both modes through V2 against the Hoodi
fork's matching collateral history. Refresh signed collateral/re-prove if live
submission requires data absent from that history.

## Local checks and Hoodi fork

The upstream 3.1 receipt is a cryptographic positive control, **not** a DCAP
guest proof. `RiscZeroV31HoodiForkTest` uses the real deployed router and verifier,
without etching or mocked calls, and deploys the patched V2 entrypoint locally
for unregistered old-selector rejection and permanent freezes in both modes.

```bash
FOUNDRY_PROFILE=fork_osaka \
DCAP_FORK_RPC=https://rpc.hoodi.ethpandaops.io \
DCAP_FORK_BLOCK=3998115 \
forge test --root evm --match-contract 'RiscZeroV31.*Test' -vv

node --test --test-isolation=none \
  scripts/deploy-dcap-v2/publish-v2.test.mjs \
  scripts/deploy-dcap-v2/deploy.test.mjs \
  scripts/deploy-dcap-v2/disable-sepolia-v11-risc0.test.mjs \
  scripts/fork-dcap-v2/risc0-v31-on-mac.test.mjs

CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo test --manifest-path rust-crates/Cargo.toml --locked \
  -p automata-dcap-zkvm --features risc0 --lib
```

Use an archive-capable RPC for this pinned block. The default `paris` test EVM
cannot execute the deployed router's modern opcodes. A skip, an RPC storage
error or an upstream receipt alone must not be counted as DCAP fork acceptance.
Fresh DCAP strict/minimal proofs and their V2 fork acceptance remain a release
gate until the Mac results are returned and tested.

### Review/regression checkpoint (2026-11-12, working tree)

- Full offline Solidity suite: 137 passed; four RPC-dependent setup skips.
- Explicit fork run: six Hoodi checks passed (upstream real receipt, tampering,
  old-selector rejection, deployment/configuration/rollback); three Sepolia legacy
  disable checks passed. These are not fresh DCAP 3.1 proof acceptance.
- Rust RISC Zero SDK library: ten tests passed, including real 3.1 receipt binding,
  wrong image/journal/proof, relabeled 3.0 receipt, dev-mode rejection, and ignored
  Bonsai-configuration rejection. The SDK derives its selector from verifier parameters.
- Node deployment/publication/disable/Mac-runner suite: 37 passed; one optional live
  Sepolia RPC test skipped. Build command/orchestration/archive checks: 7 + 8 + 9 passed;
  those use fake tools/archive fixtures, not actual Docker builds or proofs.
- Unchanged Go V2 client/parser regression passed (seven client tests, six parser
  tests and two fuzz seed suites); three Go fork integrations were skipped without
  a local deployment/proof bundle. A disk-full build attempt was rerun using a
  temporary RAM cache; test binaries were executed from their package directories.
- Source/caller review plus independent candidate review found no remaining confirmed
  bypass in this change after fixes. This is not a guarantee that the entire project
  is vulnerability-free. The structured diff scanner did not start because the
  uncommitted submodule revision differed from the parent gitlink.

No commit, push, live deployment or on-chain configuration change was performed by
this review. Fresh strict/minimal Docker artifacts and six DCAP Groth16 proofs remain
pending on the Mac. Bonsai/Boundless service availability was not exercised.

## Rollout after acceptance (no live changes performed here)

1. Freeze source commit, three lockfiles, paired-build evidence, strict/minimal
   artifacts and image IDs, setup digest, and verified proof/journal fixtures.
   Update SDK/prover tooling to the pins above; remote proving services must
   explicitly support these circuits. Do not fall back to an older service.
2. Deploy a new `AutomataDcapAttestationV2`: the already deployed non-proxy
   entrypoint cannot acquire the no-fallback rule by changing configuration.
   Prefer the [isolated coordinator](../scripts/deploy-dcap-v2/COORDINATOR.md): it
   creates six independent contracts (entrypoint, Router, PCK helper, V3/V4/V5),
   copies approved legacy fees/DAO dependencies, and adds only Storage reader
   permissions. No existing entrypoint/Router/helper is changed. This does not
   require new DAOs/storage or collateral writes. SP1/raw users can remain on
   their old V2 instance until the new instance passes acceptance. Do not copy
   old RISC Zero IDs/routes or cached roots.
3. Use the trusted fixed universal verifier. At Hoodi block 3998115 the official
   router is `0x32Db7dc407AC886807277636a1633A1381748DD8`; its repaired selector
   resolves through the emergency-stop wrapper to
   `0x8c915b5071206C6E328BC18529586c513408aB3b` (`VERSION=3.1.0`). Re-read code,
   route and pause state immediately before rollout; addresses here are not
   approval of their future state. Do not use unsafe set-aggregation routes.
4. Register the new RISC Zero strict ID with `minCheck=false` and make it default;
   register the minimal ID with `minCheck=true` without making it default. Set
   the RISC Zero verifier and explicitly add its `0xe71e6620` route to the fixed
   implementation; setting only the default verifier does not enable proofs. Test both modes,
   mismatch/tampering/old-proof rejection, pause and freezes, then enable V2 ZK.
5. Publish only verified V2 addresses/IDs/build provenance into the V2 deployment
   registry and application/SDK configuration. The universal verifier submodule
   points at the reviewed 3.1 tag. The isolated coordinator writes `PCKHelperV2`
   to the PCCS deployment file, without replacing `PCKHelper` or DAO addresses.
   Leave `current`/V1.1 defaults unchanged until the
   separately approved all-network V2 rollout and consumer migration.

Hoodi V2 had **no registered RISC Zero IDs** at the pinned block. The coordinator
now accepts an explicitly reviewed new V2 backend even when the legacy backend
is absent or disabled; it still compares unchanged legacy configuration at
publication. RISC Zero remains explicit-route-only; unregistered selectors do not
fall back to its default verifier. Program IDs and proof selectors come from the
reviewed plan, and strict/minimal entries must share the same verifier/selector.

Before freezing source/builds, review/archive the previous Hoodi `v2.0/560048`
registry record in version control. The publisher does not overwrite it, and the
coordinator checks this before sending any transaction. Use a new external run
directory and start from `scripts/deploy-dcap-v2/coordinator.example.json`.
For RISC Zero-only acceptance, populate `programs` with these two records, replacing
all placeholders from the fresh Mac output (never invent image IDs):

```json
[
  {
    "backend": 1,
    "minCheck": false,
    "buildSdkVersion": "3.1.0",
    "id": "0x<strict image ID>",
    "verifier": "0x<reviewed target-chain repaired universal verifier>",
    "proofSelector": "0xe71e6620",
    "buildSourceCommit": "<pinned source commit>",
    "artifactSha256": "<strict program SHA-256>",
    "evidenceSha256": "<strict evidence archive SHA-256>"
  },
  {
    "backend": 1,
    "minCheck": true,
    "buildSdkVersion": "3.1.0",
    "id": "0x<minimal image ID>",
    "verifier": "0x<same reviewed universal verifier>",
    "proofSelector": "0xe71e6620",
    "buildSourceCommit": "<same pinned source commit>",
    "artifactSha256": "<minimal program SHA-256>",
    "evidenceSha256": "<minimal evidence archive SHA-256>"
  }
]
```

Set `owner`/`accounts` for the deployer and distinct Storage owners; only Foundry
keystore names, never private keys. With `DCAP_RPC_URL` and `ETHERSCAN_API_KEY` set:

```bash
# Read-only checks and deployment simulation; no transactions.
node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/new-run
# After reviewing the generated plan/snapshot/readers and approving test rollout:
node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/new-run --broadcast
```

The coordinator handles deployment → additive reader authorization → strict/minimal
registration + explicit selector route → enablement → finality → source verification
→ runtime/configuration readback → versioned registry publication. Rerun the same
command after `WAIT_FINALIZATION`; completed stages are not sent again. An interrupted
broadcast needs receipt review and `--resume`, not a fresh run. This is test deployment,
not automatic acceptance or promotion. No shared universal verifier configuration is
changed. Additional SP1 programs require their own matching build provenance and proof
acceptance; they are not implicitly copied from legacy/default routes.

Do not roll back to vulnerable RISC Zero routes/receipts if validation fails;
keep that backend unregistered/disabled. Existing SP1/raw consumers can remain
on their approved deployment while the replacement is validated. Other networks
have no V2 rollout in this task; introduce only the repaired stack when they do.

## Disable Sepolia V1.1 RISC Zero (operator-signed)

This is a configuration mitigation, not a V1.1 code upgrade. The scoped script
targets chain `11155111`, Fee `0x27188ABA3a26CBb806eF4C67de9b05D7d792EC10`, and owner
`0xDf841B239bE7a6b37366005107069b7410da4Ff9`. It checks the deployed runtime hash,
reads current configuration at a pinned block, scans `ZkRouteAdded` from deployment
block 8632335, and simulates the call. Use a trusted RPC with complete historical
logs. If **any** explicit RISC Zero route was added, it stops for separate review:
clearing the default does not disable overrides. No other networks are targeted.

From the repository root, with Node and Foundry on PATH:

```bash
export DCAP_RPC_URL='https://your-sepolia-rpc'

# Read-only preflight; does not require a signer.
node scripts/deploy-dcap-v2/disable-sepolia-v11-risc0.mjs

# After checking DRY_RUN_PASS, sign with the actual owner's Foundry keystore.
node scripts/deploy-dcap-v2/disable-sepolia-v11-risc0.mjs \
  --broadcast OWNER_KEYSTORE_NAME
```

The one transaction is `setZkConfiguration(1, (existingDefaultId, address(0)))`.
It preserves the ID (never inserts zero), raw verifiers, SP1 configuration and fee.
The script waits two confirmations and verifies those fields are unchanged and
RISC Zero is disabled. Do not run concurrent owner configuration changes while
signing. Re-running without `--broadcast` safely checks for `ALREADY_DISABLED`.
Keep the transaction hash and verify finality before treating the mitigation as
permanent. RISC Zero consumers will stop working; raw/SP1 paths are not disabled.
Do not restore the vulnerable verifier as a rollback.

Local-only disable rehearsal, without a signing key or broadcast:

```bash
FOUNDRY_PROFILE=fork_osaka \
DCAP_SEPOLIA_READONLY_RPC=https://rpc.sepolia.ethpandaops.io \
forge test --root evm --offline --match-contract DisableLegacyRiscZeroSepoliaForkTest -vv
```
