# Frozen V2 verification inputs

The current expected journals use Keccak-256 for fullQuoteHash (bytes 257–288).
The quote, input and journal integrity metadata remain SHA-256. Earlier guest
artifacts/proofs using the draft SHA-256 quote slot must be rebuilt; the signed
quote/collateral and ABI inputs themselves have not changed.

These public fixtures capture the exact ABI inputs used for the local SP1,
RISC Zero and Pico execution checks. Tests need neither a PCCS/PCS endpoint nor
files left in a developer's temporary directory. They do not generate ZK proofs.

Each JSON contains the unmodified signed quote, DER certificates/CRLs, signed
TCB Info and QE Identity JSON, fixed verification timestamp, reconstructed ABI
input, expected OutputV2 **2.1** journal and SHA-256 digests. Signed JSON bodies
are preserved as strings: do not sort or reserialize their object members.
`fixtureVersion` describes this test container, not the output or Intel quote.

| Fixture | Verification timestamp | ABI input SHA-256 | Journal bytes |
| --- | ---: | --- | ---: |
| V3 | 1755236700 | `a541671d3a37b9d6f1877edfc2c600217cf58fee8488d0a2af1ef3d8fd1aad5e` | 833 |
| V4 | 1749095100 | `3e0eb6ab34f89434a9442aa06728b10fd82a97b7fb6e4ca725dfe666bab520ea` | 1225 |
| V5 | 1789052566 | `99c9630ffd878ab2800b5d72ca90d07b077ef360eec83efa116815e2200419a9` | 937 |
| ATA SGX V3 | 1789139978 | `d0ba508f6946915279d1662516b0324a1e899c073ca94e0e13b69407287aec94` | 833 |
| ATA TDX V4 (extracted prefix) | 1789139978 | `567c4e1f7ec0b70cc52e55ad3c06c0ed205b28c4f32bebe3d16efcc37e4e78ce` | 873 |

The additional ATA quote originals and explicit TDX padding extraction are
documented in [quote provenance](../quotes/README.md). The original 8,000-byte
TDX input is a rejection fixture, not the 4,935-byte successful quote committed
by `ata-tdx-v4.json`.

Both ATA snapshots use evaluation number 20 and fixed timestamp `1789139978`
(2026-09-11T15:19:38Z). SGX FMSPC `00606a000000` and TDX FMSPC `00806f050000`
TCB Info plus their respective QE identities were obtained directly from Intel
PCS API v4 on 2026-09-11. Root/platform CRLs and the signing/root certificates
are reused from the authenticated `v5.json` snapshot captured on 2026-09-10;
the new responses' issuer chains were independently checked against those
certificates. Full native and Solidity verification authenticate this combined
snapshot at the recorded time. No claim of validity at arbitrary future fork
timestamps is made.

## Provenance and scope

- V3/V4 reuse this repository's `assets/v2/quote-v3.hex`, `quote-v4.hex` and
  existing signed Intel collateral snapshots at source commit
  `81646e5754a8124d4a70a483882f11b515c98c7b`. Expected journals also match the
  existing `assets/v2/verified-v3.hex` and `verified-v4.hex` vectors.
- V5 is Google's public, unmodified
  [go-tdx-guest sample at commit 48f3644ca143b4800def5f89dca819294606bf4e](https://github.com/google/go-tdx-guest/blob/48f3644ca143b4800def5f89dca819294606bf4e/testing/testdata/quote_sample_v5.dat),
  redistributed as hex under Apache-2.0. The license text is included in this
  repository at [dcap-rs/LICENSE](../../../../../rust-crates/libraries/dcap-rs/LICENSE).
  Quote SHA-256 is
  `cf77a6e91e48291d5d338c5f3b5d0674225a4d13e7d83ff5e537a4914bf22e1d`.
  Its matching Intel PCS API v4 collateral was captured on 2026-09-10. This is
  Quote V5, TDX 1.5 body type 3, 648-byte body and zero MR_SERVICE_TD.
- Public PPID/PIID values are intentionally retained for identity parity.
  There are no private keys, API credentials or private machine quotes here.
- These historical timestamps exercise validity at that time, not current
  freshness, challenge binding or a full provider-provenance policy.

## Offline regressions

From the repository root, after dependencies have been fetched:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test --locked --offline \
  --manifest-path rust-crates/Cargo.toml -p dcap-rs \
  --lib --test output_v2 --test guest_fixtures_v2 --target-dir rust-crates/target
forge test --root evm --match-contract QuoteV5PublicFixtureV2Test -vv
forge test --root evm --match-contract 'PublicAta(SgxV3|TdxV4)Test' -vv
go test ./go-sdk/packages/godcap/parser
```

The Rust tests rebuild all five ABI inputs from their individual components,
check digests and compare verification against the frozen expected bytes. They
also reject a changed signed body and a timestamp before certificate validity.
The two ATA inputs additionally cover the shared eight-case mutation matrix.
Their frozen TCB statuses are SGX `OutOfDate` (1) and TDX `UpToDate` (0);
successful verification is not an assertion that every platform is up to date.
The Solidity V5 test uses real PCCS DAOs, collateral signatures, certificate
verification and FeeV2; no RPC or cryptographic mocks are involved. It selects
the snapshot's evaluation number **20** explicitly. Automatic selection using
TCB evaluation-number collateral remains part of the future fork acceptance.

## Export inputs for any of the three guests

```sh
fixture_output_dir="$(mktemp -d /tmp/dcap-v2-fixtures.XXXXXX)"
for quote_version in 3 4 5; do
  cargo run --locked --offline --manifest-path rust-crates/Cargo.toml \
    -p dcap-rs --example v2_fixture --target-dir rust-crates/target -- \
    export "evm/forge-test/assets/v2/fixtures/v${quote_version}.json" \
    "$fixture_output_dir/v${quote_version}-input.bin"
done
for sample in ata-sgx-v3 ata-tdx-v4; do
  cargo run --locked --offline --manifest-path rust-crates/Cargo.toml \
    -p dcap-rs --example v2_fixture --target-dir rust-crates/target -- \
    export "evm/forge-test/assets/v2/fixtures/${sample}.json" \
    "$fixture_output_dir/${sample}-input.bin"
done
```

Pass an exported file to the execution-only runners documented under
[SP1](../../../../../rust-crates/libraries/zkvm/methods/sp1/README.md),
[RISC Zero](../../../../../rust-crates/libraries/zkvm/methods/risc0/README.md) or
[Pico](../../../../../rust-crates/libraries/zkvm/methods/pico/README.md).
The SP1/RISC Zero runners support `--negative`: signed-body/signature changes,
trailing zeros, truncation, unsupported quote version, oversized signature
length, and pre-/post-validity timestamps (eight cases). Pico's current runner compares
successful execution only. Guest ELF/native ID approval and real proof checks
are separate gates.

## Deliberate fixture maintenance

To capture a new authenticated ABI input, use:

```sh
cargo run --locked --manifest-path rust-crates/Cargo.toml -p dcap-rs \
  --example v2_fixture --target-dir rust-crates/target -- \
  capture /path/to/input.bin /path/to/new-fixture.json 'Public source, immutable revision, collateral capture date'
```

Capture performs native verification and an exact reconstruction check before
writing. Export additionally checks against the expected journal. Both refuse
to overwrite an existing file. Tests never invoke capture or refresh collateral;
changes to expected results must be reviewed against signed source data and
independent Solidity/guest execution, not accepted merely by regenerating JSON.
