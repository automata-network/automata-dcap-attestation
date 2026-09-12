# Public ATA quote validation record

Git retains this record, text checksum manifests and the referenced test
sources/fixtures, not the complete `validation.tar.gz`. The optional archive
remains local and ignored; it is not deleted. No archive download or external
storage is required for the [repeatable regression commands](../../../../dcap-v2-public-quotes-validation.md#repeatable-commands-and-fork-handoff).
ABI inputs are exported offline from the checked-in signed fixtures. Test
toolchains and canonical guest programs are separate prerequisites.

This package records the 2026-09-11 follow-up using the user's SGX V3 and TDX V4
quotes. See the [validation report](../../../../dcap-v2-public-quotes-validation.md)
for conclusions, resource limits and remaining gates.

The optional local `validation.tar.gz` contains:

- Six execution logs: SGX and TDX on each canonical Docker program.
- Two exact exported positive ABI inputs, reconstructible from the checked-in
  fixtures without network access. These contain public PPID/PIID values.
- Rust/Solidity/Go test output, five proof-runner environment guard checks and
  fixture-tool extraction/preparation checks.
- Four Intel PCS API v4 response headers and signed TCB/QE JSON bodies. The
  full fixtures also retain the authenticated certificates and reused CRLs.
- RISC Zero/SP1 SGX local proving attempt logs and observed exit codes.
  A timeout log is retained as incomplete evidence, never as proof success.

No completed proof, setup parameters, live deployment, RPC credentials or
private key is included. The positive TDX input uses only the authenticated
4,935-byte prefix; the original 8,000-byte input remains a negative fixture
in the repository. Pico covers local positive execution only.

If you obtain the optional archive separately, verify it from this directory
with `sha256sum --check SHA256SUMS` (macOS: `shasum -a 256 -c SHA256SUMS`).
That command expects the archive to exist; it is not a fresh-checkout test.
`SOURCE_SHA256SUMS` records textual fixture/test/runner/lock hashes from the
**historical execution snapshot**. On that source snapshot, check it **from
the repository root**:

```sh
sha256sum --check docs/evidence/dcap-v2/2026-09-11/ata-quotes/SOURCE_SHA256SUMS
```

This source manifest is the **historical execution/600-second-attempt snapshot**,
not a rolling manifest of later edits. The extended serial proof retry added
SP1 host progress logging, a default-FRI guard and proof-commitment rejection;
its `sp1_v2_prove_local.rs` hash therefore differs intentionally. The original
manifest and `validation.tar.gz` remain unchanged. See the separate
[extended proof evidence](../ata-proofs/README.md) for that runner and its
current source manifest, which is the one to check on the current tree.
Guest programs, locks, fixtures and input bytes did
not change between these attempts.

Guest source is frozen at `81646e5754a8124d4a70a483882f11b515c98c7b` and program
bytes/native IDs are recorded in the validation report. The local test/harness
changes are not a new guest release. Canonical program binaries remain in the
previous Docker build record. Source/build procedures, hashes and the test
summary remain in Git; full historical archives are optional local audit
material. A summary alone is not independent proof of the recorded test run.
