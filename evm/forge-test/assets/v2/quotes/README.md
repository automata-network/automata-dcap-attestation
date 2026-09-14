# Public ATA quote inputs

The user supplied these public attestation hex strings on 2026-09-11. Originals
are preserved byte-for-byte, including their hex prefix/formatting. These are
public attestation data, including PPID/PIID, not private keys. No additional
upstream license assertion is inferred from their public availability.

| File | Source | Decoded bytes | Intended V2 use |
| --- | --- | ---: | --- |
| `ata-sgx-v3.hex` | [SGX transaction](https://attestation.ata.network/attestations/tx/0x22c268ea4272af0ee2f1ae7ec9a3abccc1ab8f8353e6f51b1c317abc237aa7a8) | 4,734 | Authentic SGX V3 positive fixture |
| `ata-tdx-v4.hex` | [TDX transaction](https://attestation.ata.network/attestations/tx/0xb9f8b6d05ed2511b712c14b884acb55dd96c58339f7db818ef2d77de05fc34d2) | 8,000 | Original padded input: strict V2 rejection |
| `ata-tdx-v4-extracted.hex` | Explicit prefix of the preceding input | 4,935 | Authentic TDX V4 / TD 1.0 positive fixture |

The TDX header/body and declared signature length consume exactly **4,935 bytes**.
The original input adds **3,065 zero bytes**. The extracted file is exactly the
declared prefix; no signed byte or signature was changed. Both quote and QE
signatures verify, followed by full production-policy/collateral verification
on the extracted prefix. This is an explicit fixture transformation, not a
change to verifier behavior: supplying the original 8,000 bytes to V2 must fail.
Its `fullQuoteHash` must not be confused with the extracted quote's hash.

Decoded-byte SHA-256 (not the hash of the textual hex file):

```text
SGX original: 93aeaad2128ee866149de0491f4857ebc90e9336adec003919e4f47f3289b550
TDX original: 2e2d900ec5700cf69cf4234c56cb4411fb474b7fa03f7c3679ff73aa3de5d5e1
TDX extracted: 4538f18e97ebc66dcec1a00c5e5d942784a5e8ca507221b090d128a4081f8dc8
```

The matching full collateral/input/journal fixtures are
[`ata-sgx-v3.json`](../fixtures/ata-sgx-v3.json) and
[`ata-tdx-v4.json`](../fixtures/ata-tdx-v4.json). Both use Platform CA and require
PIID. They do not add Processor CA/PIID-absent or Quote V5 coverage.

## Repeat inspection or deliberate extraction

From the repository root:

```sh
cargo run --locked --offline --manifest-path rust-crates/Cargo.toml \
  -p dcap-rs --example v2_quote_input -- \
  inspect evm/forge-test/assets/v2/quotes/ata-tdx-v4.hex
```

Inspection reports framing and verifies quote/QE signatures, not full Intel
chain, revocation or production policy. The separate `extract-zero-padding`
command requires a nonempty, all-zero suffix, verifies signatures, and refuses
to overwrite its destination. Normal verification never calls this command.

Use the existing `v2_fixture export` command for offline positive inputs.
The new `v2_quote_input prepare` command accepts a quote, an existing signed
collateral snapshot, replacement signed TCB/QE JSON, timestamp and new output
path. It reuses the snapshot's CRLs/signing chain, rejects trailing quote bytes,
and writes only after full native V2 verification. It does not fetch collateral
or guess compatible certificates; `v2_fixture capture` explicitly freezes the
result afterwards. Regression tests never refresh fixtures or expectations.
