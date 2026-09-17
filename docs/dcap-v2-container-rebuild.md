# V2 reproducible Docker builds

> Superseded checkpoint: the minCheck/Keccak revision changes guest semantics,
> fullQuoteHash and the long V2 selectors. Build IDs, proofs, fork acceptance
> and gas results below are historical, not acceptance for the current source.
> See [current revision and release gates](dcap-v2-min-check.md).

The revised `359def3` official-image builds and exact-program guest regression
are recorded in [the current build report](dcap-v2-current-build.md). The old
IDs/results below must not be used for the minCheck/Keccak deployment.

## Agreed release criterion (corrected 2026-09-11)

Freeze the image **digest and platform**, source commit, lockfiles, build flags
and SDK/tool versions. Build the same source in **two fresh containers using
that same image**, without reusing guest targets or compiled build layers, then
compare the complete artifacts and native IDs. Source locations inside each
container are fixed by the build recipe. Record Docker/CLI versions as evidence.

The result does **not** have to match an arbitrary host-native build. The earlier
host/container comparison tested a stronger, different property and is not a
failure of the team's Docker-only release process. Do not change guest code or
path normalization merely to reproduce the old host candidate. Investigate
determinism only if the two builds under the agreed fixed environment differ.
Guest execution parity and real-proof verification are separate release gates.

Release scope confirmed 2026-09-11: production remains limited to RISC Zero/SP1
on their existing supported networks. Pico stays local-only; retain its build
and execution evidence, but no Pico network deployment/registration or
existing-deployed-verifier parameter recovery is required. Local Pico proof
testing remains separate and must not be reported as passed by execution alone.

## Pinned release-build environments

| Backend | Builder | Platform |
| --- | --- | --- |
| RISC Zero | Official `risczero/risc0-guest-builder:r0.1.88.0` | `linux/amd64` |
| SP1 | Official `ghcr.io/succinctlabs/sp1:v5.2.2` | `linux/amd64` |
| Pico | Repository `methods/docker/Pico.Dockerfile`; Rust base plus preinstalled nightly-2025-08-04 | `linux/arm64` |

Resolved immutable image references:

```text
risc0 risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3
sp1   ghcr.io/succinctlabs/sp1:v5.2.2@sha256:7b5582c3773b0238192fbd5d6a37f5eb3166d3a47a1a1798ecc7847d2194d04f
pico  sha256:5267d5a6bf10f90419dd8efac398e0ae3a6bfadb3fcf9b0fcdb59cef5aaa2283
```

SP1's multi-manifest index digest is
`sha256:8910f5c53f9f3685c87394bd56027636c09c6f9178557e656040e12730443fc2`;
the pinned executable platform manifest is the AMD64 digest above. Its other
manifest is an attestation, **not an ARM64 image**. RISC Zero's resolved image
configuration also reports AMD64. Pico's reference is a locally built immutable
image ID, not an already-published registry image. Archive/export or publish that
exact image before another worker needs it; a fresh image build is not assumed
to have the same image digest. Do not use `latest`.

### Official RISC Zero and SP1 paired builds

Use an AMD64 Docker worker or a working AMD64 emulation environment, with the pinned host orchestration CLI installed:
`cargo-risczero` / `r0vm` 3.0.3 or SP1 CLI v5.2.2 (`bb91c6f`). The CLI only
orchestrates guest Docker compilation and computes the native ID. RISC Zero
also performs its standard 3.x user/kernel packaging; preserve the resulting
`guest.bin`, not the raw user ELF. CLI binary hashes are recorded in the results.
SDK 3.0.3 queries the local rzup Rust version while choosing the atomic-lowering
flag, so select the matching RISC Zero Rust 1.88 component on that worker too;
it is not used to compile the guest outside Docker.
Host Cargo metadata is pinned to 1.88.0; this does not change the compiler or
Cargo supplied by either official image. In particular, SP1's official image
uses Cargo 1.90.0 with its Rust 1.88-dev compiler.

For the Apple Silicon Mac, see the [portable handoff instructions](../rust-crates/libraries/zkvm/methods/docker/README.md).
The handoff exports the selected committed source and separately hashes the
current harness, so uncommitted harness files do not have to be pushed first.
It resolves macOS directory aliases, supports `shasum`, normalizes native-ID CLI
presentation, and exports compact evidence archives on success/build failure.

```sh
bash rust-crates/libraries/zkvm/methods/docker/reproduce-official.sh \
  risc0 81646e5754a8124d4a70a483882f11b515c98c7b
SP1_CARGO_PROVE=/path/to/v5.2.2/cargo-prove \
  bash rust-crates/libraries/zkvm/methods/docker/reproduce-official.sh \
  sp1 81646e5754a8124d4a70a483882f11b515c98c7b
```

The harness uses each pinned SDK's **official Docker build path**. It exports
two source trees from one immutable Git archive. A per-job Docker wrapper forces
`--no-cache --platform linux/amd64` for RISC Zero's Docker builds; SP1 uses fresh
containers and separate source/target directories. It does not prune shared
caches or change the daemon. Actual guest Cargo builds are locked, and unchanged
lockfile hashes, artifacts and native IDs are checked. Dependencies may need
network access. Scripts and their input hashes accompany the results; source
comes from the requested commit, not uncommitted working-tree changes.

Linux ARM64 worker limitation (historical preflight): the official
SP1 image was pulled successfully, but even `/bin/true` returns
`exec format error` on this ARM64 host. The harness correctly stops there. An
AMD64 worker or separately approved/configured AMD64 emulation is required;
no privileged container, binfmt installation or Docker socket mount was used.

The separate Apple Silicon Mac has now completed both official-image A/B builds.
The returned evidence records macOS 26.6.2 (25G83), Docker Desktop 4.90.0
(238679), engine 29.7.2, with Apple Virtualization framework and Rosetta enabled
per the user. Both pinned images report `linux/amd64`. The Docker VM still
reports 18 CPUs and 8,317,267,968 bytes of RAM (about 7.75 GiB); the recommended
12-GiB allocation was **not** the configuration evidenced by these successful
runs. No rebuild is required merely to increase that allocation.

### Returned Mac build evidence (2026-09-11)

Both archives were independently checked after transfer. Each records exit
status zero and a successful comparison. Checks included actual A/B artifact
bytes and SHA-256 values, normalized native IDs, guest lock hashes, immutable
image references/platforms, and the source archive hash regenerated from local
Git. The archived harness matches both its recorded hashes and the local handoff
scripts. Archive paths and member types were checked before extraction;
AppleDouble `._*` files and extended attributes were ignored as Mac metadata,
without modifying the program bytes.

```text
source commit: 81646e5754a8124d4a70a483882f11b515c98c7b
source archive SHA-256: d2acdb04c97989118cf9fadcdd4d693e0412c0255efa8b5dad37db26751e5e14
common.sh SHA-256: 7e2cd2461d5fa96f3f131d49d3219684262ad1df6902d508b73498d9da8d9a1b
docker-no-cache.sh SHA-256: 9076b829db4db7e4edd91aca0161b2bc3e229af5c63d18fa8ba8a2e54b3db822
reproduce-official.sh SHA-256: 2c5b74b281090713a497eb77f1d919d8f6f3dced7583a6156a171daf58e8efde

risc0.evidence.tar.gz SHA-256: 6cc8dd4aa19fb794c96ad83b50523d4585c79cb1411a16f59f378b49382b73c0
risc0-session.log SHA-256: e7b8f5c635ef422c6326adc60c77249cf52969717bb18e9a3dfea3d44961163b
sp1.evidence.tar.gz SHA-256: 18105aa65a23f94fd242948548c67fe0176e57667649d12935494445cd39d488
sp1-session.log SHA-256: 8437546f33655413c1552815ff60d0b2bedefeaa482e4e0f2221ecaf7c55689a

RISC Zero A/B program bytes: 1866092
RISC Zero A/B SHA-256: 0560682c1b2edee108406f66cd3d174671941da2267846ebd076e6b335762371
RISC Zero A/B image ID: 0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b
RISC Zero guest lock SHA-256: b1effad0065ea61600220be04a4610f260b8089aeec996bc3a8ffa5a0e80f190

SP1 A/B ELF bytes: 1776248
SP1 A/B SHA-256: 95f7c4bd575fe4bbe9bcb55538941213c5c7cf49bd929dde811b9fb85ad2f69f
SP1 A/B program VKey: 0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170
SP1 guest lock SHA-256: d7aadb020fc6f848e600eb423274c3701a9aa0fd24865aa087e5944258f7e20f
```

The logs show fresh guest compilation for both runs, not just a repeated hash
of one cached program. RISC Zero's B log marks only `WORKDIR /src` as `CACHED`;
source copy, locked dependency fetch and locked compilation actually ran. SP1
uses distinct A/B source and target directories. The RISC Zero program above
is the complete SDK 3.x `guest.bin`, not a raw user ELF.

These hashes identify Docker-built candidates for the frozen source, not
approved on-chain registrations. Preserve the original evidence archives and
bind source, harness, locks, image/platform and native IDs in the final release
manifest. If guest source, dependencies or the build recipe change, repeat the
paired builds and execution/proof checks for the resulting artifacts. No old
host candidate or embedded legacy program was overwritten.

### Returned-program execution (2026-09-11)

Executed the exact returned A programs against all three authenticated fixtures,
and independently executed each B program against V5. Inputs were freshly
exported from the [frozen fixtures](../evm/forge-test/assets/v2/fixtures/README.md);
the exporter reconstructs each ABI input and checks native verification against
the immutable expected journal before writing. All three exported input hashes
match the fixture records. Verification timestamps are fixed historical values,
not a claim that the collateral is valid at the current time.

The Linux ARM64 execution-only runners use RISC Zero SDK/local `r0vm` 3.0.3 and
SP1 SDK 5.2.2, with `RAYON_NUM_THREADS=2`. The core, runner sources and host lock
are unchanged from `81646e5`; existing host runner binaries were reused, not
rebuilt in this audit. Their independently computed image IDs/program VKeys
match the Mac CLI results for every run. SP1 reports circuit version `v5.0.0`,
with default circuit shapes and VK checks enabled. No DEV_MODE, mock receipts,
network prover or proof generation was used. RISC Zero required local
subprocess/loopback IPC permission only.

| Program copy / quote | RISC Zero user cycles | SP1 cycles | Journal bytes (each) | Exact native/fixture parity | Rejection cases (each backend) |
| --- | ---: | ---: | ---: | --- | --- |
| A / V3 | 14,339,762 | 14,482,696 | 833 | PASS | 2/2 PASS |
| A / V4 | 13,784,251 | 13,944,647 | 1,225 | PASS | 2/2 PASS |
| A / V5 | 14,309,129 | 14,450,166 | 937 | PASS | 2/2 PASS |
| B / V5 | 14,308,966 | 14,450,166 | 937 | PASS | 2/2 PASS |

All eight successful executions decode as OutputV2 **2.1**, with the expected
Intel quote version and `piidPresent = true`. Each also rejects both a changed
signed quote body and a pre-validity verification timestamp: **16 rejection
checks passed**. Expected guest validation panics in the logs are negative-test
successes; arbitrary VM faults, IPC failures and cycle exhaustion do not count.
SP1 also prints its SDK random-generator warning; this audit does not establish
proof-generation or randomness security. Cycle equality is not a build/parity
criterion, and cycles from different VMs are not directly comparable.

Local logs and the exact exported ABI inputs are archived unchanged in
[guest-validation.tar.gz](evidence/dcap-v2/2026-09-11/guest-validation.tar.gz),
with [provenance and checksum instructions](evidence/dcap-v2/2026-09-11/README.md).
The original `/tmp/dcap-mac-evidence.zVIc3F/guest-validation.tar.gz` is no longer
the only retained copy. Keep the separately supplied Mac build archives and
session logs alongside this execution evidence for a complete release record:

```text
guest-validation.tar.gz SHA-256: e254179147cb34d6ef0ca59872dd482f79c8d78e7ad69e2c60cbcdd61d2831c8
risc0_v2_execute binary SHA-256: 0f7ff7ac9dd4fc5c05797f9c88dcc912087f84ba995e40fe98cb9e41a79d0e46
sp1_v2_execute binary SHA-256: 4f200ea7f0f417914a141ec868cb17b6c59b076630248583381e941edc4cb2ab
v2_fixture binary SHA-256: 76f0cf5375beb66cb89dde15713a840ef0ed338ccd08b3443d734af223759ef1
```

The paired-build and stated guest-regression checks now pass for these frozen
RISC Zero/SP1 artifacts. Real receipts/proofs against the intended universal
verifiers and FeeV2, final release metadata and the deferred end-to-end fork
acceptance remain open. This audit neither deployed contracts nor registered
native IDs, and did not replace SDK artifacts or deployment defaults.

### Pico paired builds

The Pico image includes the fixed nightly and rust-src at image build time;
test containers never install compilers or mount host toolchains/caches.

```sh
docker build --platform linux/arm64 --iidfile /tmp/dcap-pico-builder-image-id \
  -f rust-crates/libraries/zkvm/methods/docker/Pico.Dockerfile \
  rust-crates/libraries/zkvm/methods/docker
repro_pico_image="$(< /tmp/dcap-pico-builder-image-id)"
bash rust-crates/libraries/zkvm/methods/docker/reproduce-pico.sh \
  81646e5754a8124d4a70a483882f11b515c98c7b "$repro_pico_image"
```

The same frozen image is used for both runs; the script refuses mutable tags.
Each container has empty source/target state, its own downloaded dependencies,
the same internal paths and 4-CPU/8-GiB limits. It checks both artifact bytes
and compiler/lock evidence. Compute native IDs with the pinned Pico SDK and
verify guest journals before treating the result as a release candidate.

Paired build result: **PASS (byte-for-byte)**. Both fresh containers completed
and matched compiler/lock evidence at `/tmp/dcap-pico-docker-pair.CXtc9e`.
Docker client/server were both 29.4.0. Builds took 8m04s and 5m32s; download and
compile time differences are not output differences. Both containers are stopped
and retained for inspection; neither shared guest targets nor mounted host tools.

```text
source commit: 81646e5754a8124d4a70a483882f11b515c98c7b
source archive SHA-256: d2acdb04c97989118cf9fadcdd4d693e0412c0255efa8b5dad37db26751e5e14
Dockerfile SHA-256: 5a22e0d92ff1d5a72852746701e67b2fdd7d10f876dd8519f24e5975a6fa72ec
inner script SHA-256: 1e644c6f4f50feca3cb098d3a5cc471438070407a15d45243f27b5e4a93ff3a4
guest lock SHA-256: 37e02e2bff69a84992af9811c9a095ef2a522de227d7b8f1d98c6629537a907f
driver lock SHA-256: 4117b6cfd99b79d9ad1d5299f03fe8c617855cdcab5447a6674456a1e7f728ba
run A ELF SHA-256: 8d0dc7c137e1a2b3f336acc05ac82125833f385201cd11a5bfbf1e02128b31b4
run B ELF SHA-256: 8d0dc7c137e1a2b3f336acc05ac82125833f385201cd11a5bfbf1e02128b31b4
run A SDK native ID: 0x000e95d6b7f85b7a9302081b512ab1dff0fad9759b89411d083760c7d554efd6
run B SDK native ID: 0x000e95d6b7f85b7a9302081b512ab1dff0fad9759b89411d083760c7d554efd6
```

Both A and B passed independent SDK native-ID computation and authentic Google
V5/native journal parity (937 bytes, 179,886,646 cycles each). These checks were
completed in the earlier Pico follow-up, not rerun during the Mac archive audit.
Pico's current execution runner covers successful execution only. These are
build/execution results, not real proofs
or permission to register an ID. Five script guard/command-shape tests also pass:

```sh
bash rust-crates/libraries/zkvm/methods/docker/test-commands.sh
```

Those smoke checks do not execute Docker or cryptographic verifiers; they are
not substitutes for the actual paired builds or proof tests.

## Historical host/container diagnostic (not the release criterion)

The following preserves the first exploratory run. It used a generic Rust
container plus read-only host compiler distributions and compared with a host
candidate. It was not the official-image, container-to-container procedure above.

### Frozen inputs for the historical run

- Source: `81646e5754a8124d4a70a483882f11b515c98c7b`.
- Image: official `rust:1.97.1-trixie`, Linux ARM64, digest
  `sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f`.
- Outer host: Rust/Cargo 1.97.1. Guest Cargo 1.88.0 and Pico
  nightly-2025-08-04 + rust-src are installed inside the container.
- Existing RISC Zero `1.88.0+de85b1d3d7f` and SP1 `succinct-1.88.0` compiler
  distributions are mounted read-only. This does **not** independently bootstrap
  those two custom compilers, and it is not a separate physical machine.
- Source is exported with `git archive` to `/work/source`; no host target,
  Cargo cache or ignored artifact is used. Each backend has its own initially
  empty target directory. Cargo may reuse dependencies downloaded earlier in
  this same container, but no host build products are reused.
- No privileged mode, Docker socket, credentials, host home directory or network
  ports are mounted. Resource limits are 4 CPUs, 8 GiB RAM and 512 processes.

### Repeat the historical diagnostic only

Use a **new container name and empty container filesystem** for every independent
run. The following paths identify the tested ARM64 compiler installations; on a
different machine supply the matching compiler distributions and rzup settings.
Do not point mounts at a whole home directory or reuse host build caches.

From the repository root:

```sh
repro_repo="$(pwd)"
repro_name="dcap-v2-repro-$(date -u +%Y%m%dT%H%M%SZ)"
docker run --name "$repro_name" --cpus=4 --memory=8g --pids-limit=512 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --mount "type=bind,source=$repro_repo,target=/source,readonly" \
  --mount type=bind,source=/home/rustdev/.risc0/toolchains/v1.88.0+de85b1d3d7f-rust-aarch64-unknown-linux-gnu,target=/root/.risc0/toolchains/v1.88.0+de85b1d3d7f-rust-aarch64-unknown-linux-gnu,readonly \
  --mount type=bind,source=/home/rustdev/.risc0/settings.toml,target=/root/.risc0/settings.toml,readonly \
  --mount type=bind,source=/home/rustdev/.sp1/toolchains/taK2iAMH7W,target=/opt/succinct,readonly \
  rust@sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f \
  bash /source/rust-crates/libraries/zkvm/methods/container-rebuild.sh \
  81646e5754a8124d4a70a483882f11b515c98c7b
repro_results="$(mktemp -d /tmp/dcap-v2-container-results.XXXXXX)"
docker cp "$repro_name:/work/results/." "$repro_results/"
```

The compiler settings file must select the mounted rzup rust component. The
script uses the curl rustup backend because the default backend timed out on
this environment's toolchain download. No default host toolchain is changed.
The script itself is test tooling read from `/source`; guest/build-driver source
comes exclusively from the specified commit, not uncommitted working-tree files.

Compare `*.sha256` and native IDs to the baseline in
[progress evidence](dcap-v2-progress.md). RISC Zero's build driver records its
native image ID. Independently verify with `r0vm --elf <program> --id`. Use
the official SP1 ID tooling / pinned SDK and the Pico execution runner to compute
their native IDs; SHA-256 is not a native program identifier. Execution-only
runners can also test the exported [frozen inputs](../evm/forge-test/assets/v2/fixtures/README.md).

### Historical result

All three builds completed, and their guest lockfile hashes match the baseline.
**All three artifact hashes and native IDs differ from the host baseline.**
RISC Zero contains Cargo registry paths under
`/root/.cargo/`; Pico contains `/usr/local/cargo/` paths versus the host's
`/home/rustdev/.cargo/`. These are not merely external build-log paths; they
appear in program data. SP1 already uses upstream `-Ztrim-paths`; its mismatch
requires further investigation and is not attributed solely to those same
visible absolute paths.

Container artifact SHA-256 values (diagnostic, not release registrations):

```text
risc0 13ff49698b98e825f8a9eb74b955f7c5031c9773364e4d023361e0bdf6eeb4fc
sp1   005930b826cc2531fab210c6e3e5db33111055054cdc6ab0e0c347c1e4c8524e
pico  8d0dc7c137e1a2b3f336acc05ac82125833f385201cd11a5bfbf1e02128b31b4
```

Independently computed native IDs:

```text
risc0 0xe19c5993b95def4871353c895c4a1feba7277cffe745044cc2b5a0f01dbc2417
sp1   0x001f85277bace063e2f60339862bff50fa3b5cb188675a6342ddf47443a5a0db
pico  0x000e95d6b7f85b7a9302081b512ab1dff0fad9759b89411d083760c7d554efd6
```

All three container-built programs were executed using the pinned host SDKs
and the newly exported Google V5 input. All produced the same 937-byte journal.
RISC Zero/SP1 also rejected changed signed body and pre-validity timestamp inputs;
Pico's current runner covers successful execution only. RISC Zero reports
14,309,343 user cycles; SP1 reports 14,450,166 cycles; Pico reports 179,886,646
cycles. This is functional diagnostic evidence, not byte reproducibility or a
real proof. Cycle counts across different VMs are not directly comparable.

The completed container `dcap-v2-repro-81646e5` is stopped, with logs and artifacts
retained. Results were copied to
`/tmp/dcap-v2-frozen-inputs.qphl5P/container-results` for inspection. The original
host candidate files and native IDs were not replaced or registered.

This is evidence of a non-hermetic build input, not evidence that the DCAP
verification policy differs. It does not rule out additional sources of build
variance. Container artifacts are diagnostic candidates only; do not replace
the previous candidates or register either set as an audited release.

These differences do not require making arbitrary host builds match. The
release gate is the same-image paired build above, followed by guest/proof
checks on the resulting canonical artifacts. Freeze those Docker-native IDs
with the final source commit; the old host IDs remain diagnostic only.
