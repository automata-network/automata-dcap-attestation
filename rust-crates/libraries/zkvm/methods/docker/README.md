# Official Docker paired builds: compact V2 strict/minimal

Build each mode twice in fresh source/target trees using a pinned official image.
Compare full artifact bytes and native IDs **within the Docker pair**, never
against a host build. Guest execution, real proofs and fork acceptance are separate
gates. No deployment, registration or paid proof request occurs here.

## Exact pins

| Backend | Official image (linux/amd64) | Host tools |
|---|---|---|
| RISC Zero | `risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3` | Cargo 1.88.0, cargo-risczero/r0vm 3.0.3 |
| SP1 | `ghcr.io/succinctlabs/sp1:v6.8.0@sha256:6df25c1a71451b51488534fb94a495ffe456c05921f79c4bcb8ccafe2810870c` | Cargo 1.96.0, cargo-prove 6.8.0 (58c4aea) |

SP1 is pinned to its AMD64 **manifest**, not the multi-platform/index tag.
Its image config digest is
`sha256:bb7cf1f247ff29702d21ba33677bc3818f295debad327fa0f779d03b204bd345`;
the OCI index returned for v6.8.0 was
`sha256:eb4c4e29423a27caf6740283b1b1e693f8806f76a10dbdaa5c2d3ada8f554d56`.
The return checker distinguishes config/image ID from repository manifest digest.

These v6 pins were read from the official registry on 2026-09-18.
The updated harness has fake-tool orchestration tests; a real new v6 Docker pair
has **not yet been run**. Old v5/inline-body evidence and IDs are historical only.

## Worker preparation

Use an AMD64 Linux worker or Docker Desktop on Apple Silicon with Apple
Virtualization framework and Rosetta AMD64 emulation enabled. Run builds
sequentially, leaving host memory/disk headroom. The wrapper bounds CPU/memory
for SDK-launched containers and drops capabilities; no privileged container,
Docker socket mount or binfmt installation is required.

Install the exact tools on the chosen worker, preserving any older development
toolchains needed elsewhere:

```sh
rustup toolchain install 1.88.0 --profile minimal --no-self-update
rustup toolchain install 1.96.0 --profile minimal --no-self-update
rzup install rust 1.88.0
rzup install cargo-risczero 3.0.3
rzup install r0vm 3.0.3
sp1up --version v6.8.0
export SP1_CARGO_PROVE="$HOME/.sp1/bin/cargo-prove"
```

RISC Zero 3.0.3 queries the installed rzup Rust version even when using Docker.
The harness selects host Cargo only for metadata/orchestration; it does not
replace the official images' compilers/Cargo. SP1 v6 uses the ELF64 target.
A CLI version-query pass alone is not a successful guest build.

## Freeze and transfer source

First commit the reviewed guest sources and lockfiles. Do not freeze an old
inline-body source commit. From the development repository:

```sh
DCAP_SOURCE_COMMIT="$(git rev-parse HEAD)"
bash rust-crates/libraries/zkvm/methods/docker/prepare-official-handoff.sh "$DCAP_SOURCE_COMMIT"
```

Transfer the printed archive via the normal file-transfer mechanism. It contains
the committed source and separately hashed current harness, not credentials,
submodules, local artifacts or caches. Verify the sender-provided outer SHA-256
before extracting into a fresh directory.

On the worker, inside the extracted `dcap-official-handoff` directory:

```sh
bash run-handoff.sh risc0 strict
bash run-handoff.sh risc0 minimal
bash run-handoff.sh sp1 strict
bash run-handoff.sh sp1 minimal
```

For a repository checkout, use `reproduce-official.sh BACKEND COMMIT MODE`
without setting `REPRO_SOURCE_ARCHIVE`. Each invocation makes two clean builds,
checks unchanged locks, compares bytes/IDs and records the selected mode.
RISC Zero uses the official no-cache BuildKit path; SP1 uses
`--no-docker-cache`, fresh targets and the digest-pinned image override.

## Return and validate

Return four `evidence.tar.gz` archives, labeled by backend and mode, plus
`BACKEND-MODE-session.log`. Packaging runs on ordinary failure as well as success.
A preflight failure before a result directory exists may have only its log.
Do not send private keys, environment files or Docker credentials.

Validate each returned archive before extraction:

```sh
python3 -B verify-returned.py BACKEND ARCHIVE FULL_SOURCE_COMMIT NEW_OUTPUT_DIRECTORY
```

The checker verifies safe member paths/types, exact source/harness/lock hashes,
image identity, consistent mode and equal A/B bytes/native IDs. It does not
execute any archived script. Independently recompute the native ID during
execution of those exact returned artifacts against frozen quote inputs.
Historical archives without mode markers cannot satisfy this revision.

RISC Zero's named `risc0.elf` is the complete user/kernel `guest.bin`, not the
raw user ELF. Native ID means RISC Zero image ID or SP1 program vkey hash; neither
is the artifact SHA-256. A pair passing does not establish guest semantics,
proof validity or EVM compatibility.

## Local harness tests

```sh
bash test-commands.sh
bash test-official.sh
python3 -B test-returned.py
```

These use fake tools/archive rejection fixtures, not actual builds or proofs.
Pico's separate paired-build driver compares both strict/minimal binaries;
Pico remains local-only and is not registered by the live deployment coordinator.
