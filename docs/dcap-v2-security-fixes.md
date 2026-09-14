# Security review follow-up: V2 and Go SDK

Scope: teammate review of DCAP main `41aedff`, applied on top of the uncommitted
V2 implementation. No live deployment, registration, publication, legacy ELF
replacement, or Solana changes are part of this follow-up.

Outcome: `fixed` for the scoped E4/E5/E6, R5 host, and G1–G4 boundaries below.
This is not release approval and does not close R1. One independent read-only
candidate review found no concrete surviving bypass or regression; local checks
were rerun afterward. It is not a repository-wide security audit.

## Maintenance boundary

- EVM corrections apply only to V2 verification. Legacy selectors, acceptance
  behavior and packed outputs remain unchanged; legacy defects are not maintained.
- Solana is excluded.
- Go SDK G1–G4 are maintained, including the shared SP1/Bonsai binary decoder and
  direct callers. G5 (read-only simulation) and G6 (final on-chain proof validation)
  are not independent vulnerabilities and are unchanged.
- R1 remains a mandatory release gate: hardened guest source must yield reviewed,
  reproducible backend artifacts, native program identifiers, and real verified
  proofs. No such V2 release artifacts have been produced by this follow-up.

## Corrections

| Finding | Enforcement boundary | Compatibility |
| --- | --- | --- |
| E4 | V5 SGX rejects a missing TCB match before indexing the selected level. | V2 returns `false, TCBR`; legacy behavior is retained. |
| E5 | V2 checks QE identity through the router's existing strict content-hash getter before using its object getter. | No new router, DAO, configuration, or legacy getter change. |
| E6 | V3/V4/V5 V2 parsers bound fixed authentication prefixes, QE authentication lengths, and certification payload lengths before slicing. | Strict V2 framing and existing error codes; legacy acceptance unchanged. |
| R5 | Pico left-pads the actual big-endian digest width; configuration rejects any field other than `kb` before proving. Proving and ID generation explicitly use KoalaBear. | Existing 31-byte digest encodings are unchanged; no old ELF or registered ID is replaced. BabyBear is rejected rather than silently routed to KoalaBear. |
| G1 | Quote constructors/extractors return errors; extraction revalidates nested bounds at use; certificate extraction rejects empty/malformed chains before indexing. | V3/V4/V5, terminal PEM NUL and legacy trailing bytes outside declared payload remain supported. |
| G2 | Bonsai HTTP handling checks transport errors before dereferencing a response. | Successful responses and existing fallback status convention remain unchanged. |
| G3 | Binary readers, lengths, options, enum/digest decoders, and receipt-to-proof conversion reject invalid/truncated/unsupported input with errors. | Valid Bonsai and current SP1 receipt encodings remain unchanged; no local cryptographic verification is claimed. |
| G4 | JSON encoding errors propagate through collateral and guest-input builders to `ProveQuote`, before remote requests. | Valid JSON and little-endian guest-input bytes remain unchanged. |

Binary collections require each element to consume at least one byte. Every
repository receipt element satisfies this restriction; custom zero-width
`FromBin` implementations are not supported. Counts are checked against remaining
input before conversion, and allocation grows only as elements are decoded.

Implementation files changed in this follow-up (paths relative to the repository):

- EVM: `evm/contracts/bases/QuoteVerifierBase.sol` and
  `evm/contracts/verifiers/{V3,V4,V5}QuoteVerifier.sol`.
- Pico: `rust-crates/libraries/zkvm/src/pico/{prover,config,cli}.rs`.
- Go: `go-sdk/packages/godcap/parser/quote_parser.go`, `portal.go`,
  `bincode/types.go`, `bonsai/{client,receipt}.go`, `pccs/pccs.go`, and
  `zkdcap/{collateral,bonsai,sp1,zkproof}.go` (the latter paths share the
  `go-sdk/packages/godcap/` prefix).
- Regression tests: EVM `QuoteInputV2Test`, `CollateralFailureV2Test` and
  `AttestationFeeV2Test`; inline Pico tests; Go `types_test`,
  `client_safety_test`, `receipt_safety_test`, `quote_parser_test`,
  `input_safety_test`, `encoding_test`, `portal_safety_test`,
  `decoder_safety_test`, and the existing SP1 `client_api_test` fixture control.
- Documentation: this report and `docs/dcap-v2-progress.md`.

The patch reuses shared readers and the existing strict router getter: no new
router deployment or collateral storage/configuration change is needed.

## V2 failure semantics

The `(bool, bytes)` result is not a promise that every invalid input returns normally:

- Invalid quote framing/nested lengths return `false` with the existing reason
  codes (`QHS`, `ADS`, `ADF`, etc.). No-match V5 SGX returns `TCBR`.
- Missing/expired QE identity triggers the existing router's
  `QEIdentityExpiredOrNotFound` error. A zero hash returned by a nonconforming
  router is rejected with `false, QEIDCH`.
- Invalid OutputV2 journals still revert in the strict codec; no attempt is made
  to reinterpret them as legacy output.
- Proofs shorter than four bytes, and incorrectly sized Pico proofs, return
  failure. Cryptographically invalid proofs can revert in the universal verifier.
- Strict certificate parsing, production-policy violations, frozen routes,
  authorization/configuration errors and resource exhaustion may still revert.

Callers requiring a non-reverting application interface must handle both returned
failure and revert. The fix does not catch and hide unrelated verifier failures.

## Go source API migration

These helpers now return an additional `error`; update downstream Go source when
adopting this SDK revision. This does not change a Solidity ABI or wire schema.

| API | Return values |
| --- | --- |
| `parser.NewQuoteParser` | `(*QuoteParser, error)` |
| `parser.DetectQuoteSpec` | `(QuoteSpec, error)` |
| `QuoteParser.CertData` | `([]byte, error)` |
| `QuoteParser.CertDataOffset` | `(int, error)` |
| `bincode.ReadEnum`, `ReadUint32`, `ReadUint64` | `(value, remaining, error)` |
| `TcbInfo.Encode`, `EnclaveIdentityInfo.Encode`, `Collateral.Encode` | `([]byte, error)` |
| `BonsaiGenerateInput`, `Sp1GenerateInput` | `([]byte, error)` |

`NewQuoteParserSafe` and `DetectQuoteSpecSafe` retain their error-returning
signatures. `CertData` returns exactly the declared certificate payload, not all
remaining bytes of the quote. Generated proof/output remains a candidate until
verified on-chain; do not treat it as an authenticated journal beforehand.

## Verification

Focused regression coverage:

- V2 short/nested quote lengths for all six supported version/body combinations,
  truncation fuzzing, typed journal rejection, short backend proofs, no-match V5
  SGX with empty/nonempty levels, missing/expired QE identity and valid controls.
- Legacy EVM behavior remains covered alongside the V2 assertions. Real signed
  V3/V4 output parity remains covered. The synthetic V5 SGX test mocks P-256 to
  isolate TCB branching and is not evidence of an authenticated V5 success.
- Pico widths 0–32, oversized digest rejection, default `kb`, and non-`kb`
  rejection before ELF interpretation/proving.
- Go valid V3/V4/V5 certificate extraction, post-construction length mutation,
  truncation, empty/malformed PEM, terminal NUL and legacy-tail compatibility.
- Bonsai transport failure/success, binary truncation/oversized lengths/invalid
  discriminants, unexpected receipt variants, and unchanged valid encodings.
- G4 invalid JSON propagates through both proving backends before accessing
  uninitialized remote clients.

The retained SP1 fixture uses the old v3 envelope containing `stdin`, which main's
current decoder no longer reads. Tests explicitly reject that old envelope and
construct the current envelope by removing only the separately decoded stdin;
proof/public-value fields are preserved. This is codec testing, not proof validation.

Build/type gates: all passed (repository root unless noted):

```sh
go build ./go-sdk/...
go test ./go-sdk/packages/godcap/... -run '^$'
go vet ./go-sdk/packages/godcap/...
# rust-crates/
cargo check --workspace --offline --target-dir target
# evm/
forge build --skip test --sizes
```

Regression gates: all passed:

```sh
# evm/: 70 local tests passed; the external RPC fork test is excluded.
forge test --no-match-contract CrlV2AeneidForkTest -vv
# rust-crates/: 5 tests passed, including the three Pico regressions.
cargo test -p automata-dcap-zkvm --features pico --lib --offline --target-dir target
# repository root: local tests only; do not run credential-driven portal integration tests.
go test ./go-sdk/packages/godcap/{bincode,bonsai,parser,pccs,zkdcap,sp1,feev2,registry}
go test ./go-sdk/packages/godcap -run '^TestGenerateZkProofRejectsMalformedQuoteWithoutNetwork$'
CGO_ENABLED=1 go test -race ./go-sdk/packages/godcap/{bincode,bonsai,parser,pccs,zkdcap,sp1} -count=1
```

Four additional 10-second, two-worker fuzz runs passed:

```sh
go test ./go-sdk/packages/godcap/bincode -run '^$' -fuzz '^FuzzBinaryDecoders$' -fuzztime=10s -parallel=2
go test ./go-sdk/packages/godcap/bonsai -run '^$' -fuzz '^FuzzReceiptDecoder$' -fuzztime=10s -parallel=2
go test ./go-sdk/packages/godcap/parser -run '^$' -fuzz '^FuzzQuoteCertificateParser$' -fuzztime=10s -parallel=2
go test ./go-sdk/packages/godcap/sp1 -run '^$' -fuzz '^FuzzSP1ProofDecoder$' -fuzztime=10s -parallel=2
```

Use a writable `GOCACHE` in restricted environments. The repository-pinned missing
gRPC dependency was downloaded to run the Go checks; no dependency version changed.
Security-trigger checks on saved pre-fix Go source reproduce G1 out-of-bounds
certificate parsing, G2 transport-error nil dereference and G3 short scalar-read
panic; corresponding fixed-path regressions return errors.
The race check initially could not start with the environment's default CGO-off
setting; rerunning with `CGO_ENABLED=1` passed all six packages. Whitespace checks
and formatting checks for the changed files passed.

No live RPC fork, remote proof submission, guest rebuild, on-chain ID registration,
or full production security audit was performed. Those are separate release gates.
