# Current SP1 SGX V3 core-proof resource handoff

This resumes validation of the **returned 2026-09-17 Docker guest**, not a new
guest build. It runs a packaged ARM64 Linux host helper inside the pinned Ubuntu
ARM64 runtime. Rosetta is not needed for this host-proving step. The guest
remains the exact ELF produced by the official AMD64 SP1 Docker paired builds.

The original worker completed the current RISC Zero composite receipt. Two
SP1 attempts were safely stopped for low host available memory; neither produced
a complete proof. This handoff therefore starts SP1 core proving from the input,
not from an imaginary checkpoint. It does not rerun RISC Zero.

Use an otherwise idle Mac with **at least 16 GiB assigned to Docker Desktop**.
The proof container is capped at 10 GiB, four CPUs, no swap and no network. It
does not mount the Docker socket. Do not use this on a concurrently busy worker.

After verifying the handoff archive hash against the sender's report, extract it
into a new directory. Pull the runtime once (the proof itself is offline):

```sh
docker pull --platform linux/arm64 \
  ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
bash sp1-current-core-handoff/run-on-mac.sh \
  sp1-current-core-handoff "$PWD/sp1-current-core-result"
```

The result directory must not already exist. Return its `return.tar.gz`, including
on failure. Keep the complete handoff/result directories until independent
verification of the returned proof. A successful run includes the real core
proof, full journal parity, three rejection checks and fresh-process readback.
This is **not** an EVM Groth16 proof, live Hoodi test or release approval.

The bundle includes helper source, host Cargo.lock, source.tar for the frozen
guest-build revision, and the compact candidate/provenance record. The helper's
optional shard-size setting is a host-only change after that frozen revision;
it never changes the ELF, native ID, FRI parameters or VK/shape enforcement.
The SHA256SUMS file hashes the helper, inputs, sources and runner. Full guest
build evidence and original quotes remain in the main local evidence archive.
