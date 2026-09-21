# Docker guest regression evidence — 2026-09-11

`guest-validation.tar.gz` is the unchanged execution-evidence archive produced
after independently checking the returned Mac RISC Zero/SP1 paired builds.
It is copied here from temporary storage for versioned retention, not rebuilt
or recompressed. Verify from this directory with:

```sh
sha256sum --check SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS`.

## Contents and scope

- `execution/`: eight local execution-only logs, four per backend (A against
  V3/V4/V5 and B against V5), with independently computed native IDs, exact
  native journal parity and two rejection checks per run.
- `inputs/`: the three public ABI input files exported from the frozen
  quote/collateral fixtures. These contain public PPID/PIID values, not private
  keys or credentials. Input timestamps are fixed historical verification times.
- Result: eight successful guest executions and sixteen expected rejection
  checks. Validation panics in negative tests are expected, not failed runs.
- No proof, setup parameters, deployment or on-chain registration is included.
  Pico is not in this archive; its earlier paired-build/V5 execution evidence
  is recorded separately and its support remains local-only.

Frozen guest source: `81646e5754a8124d4a70a483882f11b515c98c7b`.
Full image, artifact, native-ID, input and runner hashes are in the
[Docker verification record](../../../dcap-v2-container-rebuild.md#returned-mac-build-evidence-2026-09-11).
See the [fixture provenance](../../../../evm/forge-test/assets/v2/fixtures/README.md)
for source/license details and repeatable input generation.

The separately supplied `risc0.evidence.tar.gz`, `sp1.evidence.tar.gz` and their
session logs are unchanged in the repository root; they have not been copied
into this additional archive. Their checksums are recorded in the verification
record. Preserve those original build archives alongside this execution archive
in long-term release evidence storage. This package alone is not a complete
paired-build record or proof-verification attestation.
