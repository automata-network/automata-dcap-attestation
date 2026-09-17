# Official Docker paired-build handoff (RISC Zero / SP1)

Build the frozen guest source twice in the same digest/platform-pinned official
image. Compare complete program bytes and native IDs. Equality with an older
host-native artifact is NOT required. Guest regression and real proofs are
separate checks; this procedure does not submit proofs, register IDs or deploy.

## Mac readiness

Use Docker Desktop for Apple Silicon, Apple Virtualization framework and the
Rosetta AMD64 emulation option. The user-reported 2026-09-11 preflight passed on
macOS 26.6.2 / Docker Desktop 4.90.0 / engine 29.7.2 with these exact images:

```text
risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3
ghcr.io/succinctlabs/sp1:v5.2.2@sha256:7b5582c3773b0238192fbd5d6a37f5eb3166d3a47a1a1798ecc7847d2194d04f
```

Both run as `linux/amd64`. RISC Zero contains Rust/Cargo 1.88-dev. SP1 contains
Rust 1.88-dev and Cargo 1.90.0: keep those image contents unchanged. Do not install
Cargo 1.88 into the SP1 image to imitate the old host build.

For headroom, **12 GiB for Docker** on a 24-GiB Mac, at least 4 CPUs and about
60 GiB of free disk are starting recommendations, not proven minimums. The
returned 2026-09-11 A/B builds actually passed with about 7.75 GiB allocated;
do not rebuild a successful pair merely to increase memory.
Run backends sequentially. SP1 containers are limited to 4 CPUs / 8 GiB; RISC
Zero's official BuildKit compilation uses the Docker VM's resource allocation.
Do not change Desktop, images or tools between A and B. Emulation can still fail
in a full compile even when a version-query preflight passes.

The previous backends' returned A/B build evidence and exact-program regression
passed only for historical source `81646e5`; see the
[verified results](../../../../../docs/dcap-v2-container-rebuild.md#returned-mac-build-evidence-2026-09-11).
Those IDs are NOT valid release candidates for the minCheck/Keccak revision.
The current handoff freezes source `359def3bce58ba269c48373817f48b7144424f14`.
Its returned A/B builds and exact-program execution now pass; real proofs remain
a separate gate. See [current evidence and IDs](../../../../../docs/dcap-v2-current-build.md).

Validate returned archives before extraction with `verify-returned.py BACKEND
ARCHIVE COMMIT NEW_OUTPUT_DIRECTORY`. It checks archive paths/types, the exact
source archive and harness hashes, pinned image/platform, guest locks, A/B bytes
and reported native IDs. It never executes archived scripts. Independently
recompute native IDs while running the returned programs against real fixtures;
the archive check alone is not guest execution or cryptographic proof verification.
Run archive rejection tests with `python3 -B test-returned.py` from this directory.

## Host orchestration tools

The official SDK Docker paths still use native host CLIs to discover Cargo
metadata and calculate IDs. RISC Zero 3.x also packages the user ELF with its
kernel on the host. These steps do NOT compile the guest natively.

On the Mac, install Rustup if absent using the official Rust installer, then:

```sh
rustup toolchain install 1.88.0 --profile minimal
cargo +1.88.0 --version
```

The harness selects this Cargo only for host metadata, without changing the
system default. Git must also be available (`git --version`); install Apple's
Command Line Tools with `xcode-select --install` if it is missing.

### RISC Zero

Install `rzup` if absent following <https://github.com/risc0/risc0>, then install
the pinned components, not an unversioned `rzup install`:

```sh
rzup install rust 1.88.0
rzup install cargo-risczero 3.0.3
rzup install r0vm 3.0.3

rustc +risc0 --version
cargo risczero --version
r0vm --version
rzup show
```

Expected: RISC Zero Rust 1.88.0-dev, cargo-risczero 3.0.3 and r0vm 3.0.3. If a
component is already installed, select it with `rzup default COMPONENT VERSION`
instead of forcing a reinstall. SDK 3.0.3 queries the local rzup Rust component
to choose atomic-lowering flags, even for a Docker build; that is why this local
compiler component is required. C++ guest tools come from the official image.

### SP1

Install `sp1up` if absent using the official SP1 installation instructions at
<https://github.com/succinctlabs/sp1>, then:

```sh
sp1up --version v5.2.2
export SP1_CARGO_PROVE="$HOME/.sp1/bin/cargo-prove"
"$SP1_CARGO_PROVE" prove --version
```

Expected: `cargo-prove sp1 (bb91c6f ...)`, the official v5.2.2 release. Do not
install v6. `sp1up` also installs its native guest toolchain; our Docker build
does not use that native guest compiler. If installation fails after the CLI is
installed, return the output instead of upgrading versions to work around it.

The pinned releases are <https://github.com/risc0/risc0/releases/tag/v3.0.3> and
<https://github.com/succinctlabs/sp1/releases/tag/v5.2.2>.

## Transfer the frozen source, not an arbitrary checkout

On the original development machine, from the repository root:

```sh
bash rust-crates/libraries/zkvm/methods/docker/prepare-official-handoff.sh \
  359def3bce58ba269c48373817f48b7144424f14
```

Transfer the printed `dcap-official-handoff.tar.gz` to the Mac by your normal
file-transfer mechanism. The bundle includes committed source at that exact
commit and the current harness as separately hashed files. It does not include
ignored/local files, `.git`, submodule contents, credentials, SDK installations,
build caches or `reports/`. Guest crates in scope do not need the Solidity
submodules. This does not require committing/pushing the harness or pulling main.
The source archive is not a substitute for freezing the eventual release commit.

On the Mac, verify the outer SHA-256 against the sender's value, then extract
into a fresh directory:

```sh
shasum -a 256 /path/to/dcap-official-handoff.tar.gz
DCAP_REPRO_WORK="$(mktemp -d "$HOME/dcap-repro.XXXXXX")"
tar -xzf /path/to/dcap-official-handoff.tar.gz -C "$DCAP_REPRO_WORK"
cd "$DCAP_REPRO_WORK/dcap-official-handoff"

bash run-handoff.sh risc0
bash run-handoff.sh sp1
```

Run each backend separately and inspect its exit status. Each invocation checks
the bundle manifest and source commit, creates two fresh source/target trees,
and uses the pinned SDK's official Docker path. RISC Zero uses BuildKit with
`--no-cache`; SP1 uses fresh containers and targets without host Cargo caches.
Both guest builds use `--locked`. Scripts work with macOS Bash 3.2 and `shasum`,
and resolve `/tmp`/`/private/tmp` directory aliases. Keep the session logs if a
dependency download, CLI check, emulated compiler or build fails.

For an existing repository checkout instead of a bundle, the equivalent command
is `bash .../docker/reproduce-official.sh BACKEND COMMIT` without setting
`REPRO_SOURCE_ARCHIVE`.

## Return evidence

Each backend prints `Results: ...` and, once that directory exists, writes an
`evidence.tar.gz` on both success and ordinary failure. Return **both backends'
evidence archives**, identifying which is RISC Zero versus SP1, and the handoff
directory's `risc0-session.log` / `sp1-session.log`. A missing-tool/checksum failure
before `Results:` is printed has only a session/terminal log. An OS kill or power
loss can prevent packaging; preserve the printed result directory in that case.

The archive contains source/image/script hashes, Docker/CLI versions, CLI binary
hashes, exit status, complete A/B build logs, lockfile hashes, A/B program files,
raw ID-tool stdout, normalized native IDs and the comparison result. It excludes
source/target/cache trees. Do not send `.env`, private keys or Docker credentials.

For RISC Zero, `risc0.elf` is the SDK's complete user/kernel `guest.bin`, despite
the `.elf` filename. Do not replace it with a raw guest ELF. Native ID is the
SDK image ID (RISC Zero) or program VKey hash (SP1), not the file SHA-256.

Success requires `exit-status.txt = 0`, a `comparison.txt` PASS, and byte-identical
A/B programs and native IDs. Then execute those exact returned programs against
the frozen real-quote fixtures and verify journals. This handoff never claims
that a real proof or an on-chain universal verifier has been tested.
