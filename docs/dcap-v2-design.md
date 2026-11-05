# [Planning] DCAP V2 with PPID/PIID Support

Release scope confirmed on 2026-09-11: retain the existing network/backend
support matrix. RISC Zero/SP1 production verification is enabled only where
already supported. Pico remains local-only: no network deployment, new Pico
V2 registration/default/route or online SDK enablement. Its local real-proof
tests are separate from production acceptance; execution parity does not count
as proof verification.

## 1. Versioning and compatibility

This change introduces three independent version concepts:

- Format version (`formatMajorVersion = 2`, `formatMinorVersion = 1`): identifies the serialized attestation output schema; see Section 3. The legacy positional layout counts as family 1 (its first word is `quoteVersion`); the new head/tail encoding is the first version of family 2.
- `quoteVersion = 3 | 4 | 5`: continues to identify the Intel quote format.
- Release/program version (`v2.0`): used for deployment metadata and ZK guest artifacts, independently of wire-format version `2.1`.

These versions must not be conflated.

The existing `AutomataDcapAttestationFee`, its public selectors, serialized output, events, verifier addresses, and ZK program identifiers will remain available.

A new `AutomataDcapAttestationV2` deployment will add:

```solidity
verifyAndAttestOnChainV2(bytes rawQuote)
verifyAndAttestOnChainV2(bytes rawQuote, uint32 tcbEvaluationDataNumber, bool minCheck)

verifyAndAttestWithZKProofV2(bytes journal, ...)
verifyAndAttestWithZKProofV2(
    bytes journal,
    ...,
    bytes32 programIdentifier,
    uint32 tcbEvaluationDataNumber,
    bool minCheck
)
```

Raw V2 methods return `(bool success, bytes output, bytes quoteBody)`; ZK V2 methods return `(bool success, bytes output)`. On raw failure no authenticated body is returned.

The short overloads always use strict verification. The long overloads replace
the previous draft signatures and append `minCheck`: `false` retains strict
behavior; `true` skips only SGX/TDX DEBUG, TDX reserved-attribute checks,
SEPT_VE_DISABLE, and MR_SERVICE_TD policy. It does not restore V1 parser,
collateral, identity or TCB-status behavior. Authentication and all other V2
checks remain mandatory. See [mode semantics and regression](dcap-v2-min-check.md).

The new V2 contract exposes no legacy verification or program-registry selectors. Existing deployed legacy contracts remain unchanged at their own addresses; V2 is not a drop-in replacement for those addresses.

Each backend registers two separate native IDs with immutable modes: strict and minimal. `addProgramIdentifierV2(backend,id,minCheck)` does not change the default. `setDefaultProgramIdentifierV2(backend,id)` accepts registered strict IDs only. `setZkVerifierV2` configures the verifier independently. Calls enforce exact ID/mode matching. Legacy/ATKJ IDs remain only on legacy contracts, never migrated into this registry.

V2 calls should emit a separate versioned event, such as:

```solidity
event AttestationSubmittedV2(
    bool success,
    ZkCoProcessorType verifierType,
    uint16 indexed formatMajorVersion,
    uint16 indexed formatMinorVersion,
    bytes32 programIdentifier,
    bool minCheck,
    bytes output
);
```

V2 calls should not emit the old event with V2 bytes, because existing log consumers may decode them as the legacy schema.

## 2. PCCS changes

Add a strict parser entry point alongside the existing `parsePckExtension`:

```solidity
parsePckExtensionWithIdentity(...)
```

It returns the existing PCK TCB fields together with:

```solidity
bytes16 ppid;
bytes16 piid;
bool piidPresent;
```

Requirements:

- PPID is mandatory and must be exactly 16 bytes.
- PIID is either absent or exactly 16 bytes.
- Duplicate PPID, PIID, TCB, FMSPC, or PCEID fields are rejected.
- Malformed ASN.1 values and wrong value types are rejected.
- The entire SGX extension sequence is traversed, including fields appearing after all required fields have been found.
- The strict Solidity parser follows the existing Rust parser's rules for known SGX fields, including SGX Type, Configuration, and nested TCB fields: validate types, lengths, duplicates, and required-field presence.
- Unknown SGX sub-OIDs are rejected.
- PPID and PIID have no additional non-zero-value requirement.
- The existing parser ABI and behavior remain unchanged.

After the PCK certificate chain has been validated, the DCAP verifier enforces:

- Platform CA leaf: `piidPresent == true`.
- Processor CA leaf: `piidPresent == false`.
- When `piidPresent == false`, serialized `piid` must be zero to maintain one canonical representation of absence.

The identity must never be accepted as caller input. It must come from the verified PCK leaf certificate.

## 3. `OutputV2` layout

See Section 12 for the existing V1 wire formats that this layout replaces on the V2 entrypoints.

`OutputV2` uses an extensible head/tail encoding identified by `formatMajorVersion` + `formatMinorVersion`, in the style proven by the downstream "ATKJ" compact output (Section 12.3). The header contains a fixed compatibility marker: `magicNumber = 0x06` at offset 4, the legacy TCB-status position. It is not the actual V2 TCB status. V2 parsers must validate this byte. Selectors, events, and program identifiers namespace the output; the slot table defines its extension points. A packed positional layout was considered and rejected — it gives future fields no safe insertion point, no forward compatibility, and forces the journal and output to diverge.

Final layout for `formatMajorVersion = 2, formatMinorVersion = 1` (integers big-endian; each logical slot has the exact byte width listed below, not a uniform 32-byte width; explicitly reserved bytes are zero):

| Offset | Size | Field | Kind | Group |
| --- | --- | --- | --- | --- |
| 0 | 2 | `formatMajorVersion` (= 2) | inline | header |
| 2 | 2 | `formatMinorVersion` (= 1) | inline | header |
| 4 | 1 | magicNumber (=6, revoked) | inline | header |
| 5 | 2 | `quoteVersion` (3 / 4 / 5) | inline | result |
| 7 | 2 | `quoteBodyType` (1 / 2 / 3) | inline | result |
| 9 | 1 | `tcbStatus` (0–9, preserving the existing status meanings) | inline | result |
| 10 | 6 | `fmspc` | inline | result |
| 16 | 16 | `ppid` | inline | result |
| 32 | 16 | `piid` (zero when absent) | inline | result |
| 48 | 1 | `piidPresent` (`0x00` / `0x01`) | inline | result |
| 49 | 4 | `advisoryIDs` pointer (uint16 offset, uint16 length; zero when empty) | tail pointer | result |
| 53 | 8 | `timestamp` (BE Unix seconds) | inline | verification-only |
| 61 | 32 | TCB Info content hash | inline | verification-only |
| 93 | 32 | QE Identity content hash | inline | verification-only |
| 125 | 32 | Root CA certificate hash | inline | verification-only |
| 157 | 32 | TCB Signing certificate hash | inline | verification-only |
| 189 | 32 | Root CA CRL hash | inline | verification-only |
| 221 | 32 | Platform/Processor PCK CRL hash | inline | verification-only |
| 253 | 32 | `fullQuoteHash` (Keccak-256 of exact raw quote) | inline | result |
| 285 | 32 | `quoteBodyHash` (Keccak-256 of exact report body) | inline | result |
| 317 | variable | `advisoryIDs` payload (absent when empty) | tail | result |

The full body is absent from output/journal/event. For raw calls it is a separate
return value; for ZK consumers the application receives it separately and must
compare Keccak-256 with `quoteBodyHash` before custom checks. No advisory hash is
added: full advisories remain committed. This revises **unreleased** format 2.1;
old test-only 2.1 decoders, proofs and deployments are not compatible.

Rules:

- The table is authoritative for this unreleased revision. After release, layout changes require explicit format versioning.
- Slot kind (inline vs tail pointer) is defined statically by the registry. A tail-pointer slot stores absolute `offset` + `length` (uint16 BE each) at the start of the slot. The `offset` refers to the position of the field —— counting from the beginning (index 0) —— within the entire output.
- Each `formatMinorVersion` pins one slot layout, so the tail start is implied by the version. Validate presence, structure, and permitted values per field; do not reject zero values universally. For example, `tcbStatus = 0` is valid, and PPID/PIID need not be non-zero.
- Compatibility: any registry change bumps `formatMinorVersion`. Strict parsers reject unknown versions; lenient parsers may read known slots and ignore the rest. A new structural paradigm = new `formatMajorVersion`.
- Canonicalization is strict: contiguous, non-overlapping, in-bounds tail payloads; reserved/unassigned bytes zero; no gaps or trailing garbage.
- A non-empty `advisoryIDs` payload starts at offset 317. Empty advisories use pointer `(0, 0)` and append no payload.
- The total encoded output length must not exceed 65,535 bytes. Reject overflow or oversized encodings rather than truncating offsets or lengths.
- Verification-only slots are filled by both paths; consumers may ignore them.
- `piid` all-zero when `piidPresent == 0`; `piidPresent` ∈ {`0x00`, `0x01`}.
- `quoteBody` payloads are expanded in Sections 12.4.1–12.4.3; the advisory encoding in Section 12.4.4.

**Version self-description.** V1 outputs start with `quoteVersion ∈ {3, 4, 5}` (implicit family 1); `OutputV2` starts with `formatMajorVersion = 2`. The disjoint first words let version-aware dual-stack parsers dispatch. The fixed `0x06` at the legacy TCB-status offset makes legacy consumers that reject revoked status fail closed; arbitrary legacy decoders must not be assumed to validate an unfamiliar schema. Future `formatMajorVersion` values must stay disjoint from the `quoteVersion` value space.

## 4. ZK `JournalV2`

The V1 journal is a separate envelope:

```
outputLength | variable verifiedOutput | timestamp | collateral hashes
```

That layout does not satisfy a strict “all fixed-length fields before variable-length fields” requirement, and it keeps the journal and the returned output as two distinct objects — in V1 the output merely happened to be a contiguous slice, which hid the distinction.

In V2, **the journal is the output**: the guest commits an `OutputV2` structure (Section 3) as the journal, with the verification-only slots populated. The on-chain ZK verifier validates the format header and canonical form, checks the verification-only slots against PCCS state at the committed timestamp, and returns the structure **verbatim**, without reconstruction or re-encoding. Both paths populate the same slots using the same field semantics.

- On-chain verification uses `block.timestamp`.
- ZK verification uses the guest timestamp employed for certificate and collateral validity checks; it need not equal the proof-submission block timestamp.
- Byte-for-byte equality is required when the raw quote, collaterals, and verification timestamp are identical.
- No new maximum-proof-age or challenge-binding policy is introduced. Collateral validity checks are not a complete freshness guarantee.
- All V2 quote versions, including Quote V3, use PCS API v4 / TCB Info v3 on both paths.
- V2 returns the actual advisory IDs from the matched TCB level, preserving their order without sorting or deduplication. Legacy paths retain their existing behavior.
- Strict V2 calls reject SGX/TDX debug mode, reserved TDX attribute bits, missing SEPT_VE_DISABLE, and non-zero MR_SERVICE_TD. Only these workload restrictions are skipped with `minCheck=true`. Every backend has distinct compile-time strict/minimal programs. The contract checks mode against the registered ID before proof verification. Raw strict workload checks remain on chain; ZK strict workload checks execute inside the strict guest. Legacy contracts retain their existing acceptance policy.
- V2 TDX status calculation retains the first SGX/PCE partial-match status, enforces revocation on the complete TDX match, evaluates the matching module identity including TDX_00, and performs the relaunch check using the pre-convergence platform status. Relaunch results 8/9 must not be overwritten by legacy status serialization.
- V2 requires exact raw-quote and authentication-data framing; trailing bytes are rejected rather than silently removed before calculating fullQuoteHash.

Validation must reject:

- Unknown `formatMajorVersion`, unsupported `formatMinorVersion`, or a compatibility marker other than `0x06`
- A quote version that does not match the selected quote verifier
- Invalid `piidPresent` bytes other than `0` or `1`
- Non-zero PIID when `piidPresent == false`
- Non-canonical slots: non-contiguous or overlapping tail pointers, out-of-bounds pointers, non-zero reserved/unassigned bytes
- Invalid quote/body version combinations; raw/guest parsing enforces exact body length before hashing
- Malformed advisory ABI data
- Unexpected trailing bytes or total encoded length above 65,535 bytes
- Collateral hash mismatches or a committed timestamp outside the applicable collateral validity intervals

## 5. Contract impact

### New deployments per chain

Six new contract instances are required for isolated deployment:

1. Identity-aware `PCKHelper`
2. `V3QuoteVerifier`
3. `V4QuoteVerifier`
4. `V5QuoteVerifier`
5. `AutomataDcapAttestationV2`
6. An independent `PCCSRouter` pointing to the existing DAOs and new helper

All quote verifiers are deployed together. Compact serialization and journal/
collateral checks reside in AttestationV2. Internal quote-verifier envelopes
remain `(ppid, piid, piidPresent, legacyFields)`; applications do not decode them.

### Existing contracts

Never switch the shared Router/helper during isolated rollout. Authorize the
new entrypoint and three quote verifiers on the independent Router. Deduplicate
the shared DAOs' resolvers and add only new Router reader permission, using each
resolver's actual owner. No writer permission or collateral updates are needed.

### Contracts not requiring replacement

The following should remain unchanged:

- PCCS DAOs and storage contracts
- PCS/PCK DAOs
- CRL helpers
- FMSPC/TCB helpers
- P-256 verifier
- RISC Zero universal verifier contracts where compatible; SP1 v6 needs an explicitly reviewed compatible route/verifier (do not assume v5 compatibility)
- Pico verifier source/local test support (no network deployment in scope)

Reuse the applicable existing RISC Zero/SP1 universal verifiers and register
their new audited strict/minimal guest IDs only on supported networks. SP1 guest/build/host SDK targets exact 6.8.0 and requires a 64-bit toolchain, matching patches and v6 proof verifier. Pico's
new guest/native ID is for local validation, not a network registration.

If `DcapPortal` must directly expose the V2 methods, its implementation, ABI and proxy deployment form a separate downstream upgrade. Direct calls to `AutomataDcapAttestationV2` do not require this.

## 6. Repository impact

Estimated production scope, excluding tests and deployment JSON:

- PCCS repository: approximately 3–5 Solidity/script files.
- DCAP EVM layer: approximately 10–14 Solidity/script/interface files.
- Rust verification and ZK layers: verifier/SDK changes, three guest source/build projects, and the required shared input types, host/guest feature separation, and workspace configuration.
- Go SDK: V2 direct-call support, output/journal parsing, bindings, and network/version registries.
- Isolated `v2.0` guest artifacts: RISC Zero/SP1 production candidates and a Pico local-validation artifact; existing V1 ELF files must not be overwritten.

Re-estimate the previous 35–50-file production scope after accounting for guest source/build projects and their supporting changes, plus tests and deployment metadata. TeeVerifier application, DcapPortal, and Solana upgrades are outside this release.

The missing main-branch guest projects have been located in staging at [`rust-crates/libraries/zkvm/methods`](https://github.com/automata-network/automata-dcap-attestation/tree/942d42c8a8543a28ed737db515fb8e8c246aca61/rust-crates/libraries/zkvm/methods). Selectively port these projects and their required shared input types, feature separation, and workspace configuration; do not merge unrelated staging changes or SDK upgrades.

The staging guests originally emitted a legacy-style journal with an appended Keccak-256 quote hash. V2 guests use the agreed OutputV2 format with Keccak-256 fullQuoteHash. Their build scripts target the new release directory without overwriting or silently reusing legacy ELF files. Source availability does not establish reproducibility; reproducible builds remain a release gate. Earlier SHA-256 and inline-body guests/IDs/proofs must not be registered for this compact revision. Rebuild and re-prove before release. RISC Zero's `sha256(journal)` remains unchanged.

## 7. Deployment configuration impact

There are currently 28 configured networks: 15 testnets and 13 mainnets.

For a side-by-side rollout, retain the existing keys and add:

`onchain_pccs.json`:

```
PCKHelperV2
```

`dcap.json`:

```
AutomataDcapAttestationV2
PCCSRouterV2
V3QuoteVerifierV2
V4QuoteVerifierV2
V5QuoteVerifierV2
```

This means:

- 28 `onchain_pccs.json` files updated.
- 28 `dcap.json` files updated.
- 56 active deployment files in total.
- Another 56 files should be added as a frozen `v1.1` snapshot before `current` is promoted to the new release.
- Rust and Go network/version registries must gain the new release and V2 address fields.
- Record all three guest binary hashes/native IDs, source commits and build toolchains in build evidence, marking Pico local-only. The manifest records untouched legacy state and new strict/minimal IDs with the strict default; it does not migrate legacy/ATKJ IDs. Do not populate Pico defaults, routes or registrations.

Old address keys must not be replaced during the compatibility period.

## 8. Estimated on-chain operations

The coordinator in `scripts/deploy-dcap-v2/deploy.mjs` performs preflight,
simulation, isolated deployment/configuration, additive reader grants, finalized
readback, explorer source verification and versioned publication. Source/config
and successful stages are checkpointed; interrupted sends require reviewed resume.

Operations include six deployments, new Router authorization/evaluation mappings,
quote-verifier and fee setup, one grant per distinct unauthorized resolver, and
separate verifier/strict/minimal/default registration operations. Count and gas
depend on the evaluation/backend inventory; do not reuse old transaction totals.
Only `v2.0` and additive PCCS `PCKHelperV2` metadata are written; `current` is
not promoted. No live deployment is authorized by implementation work.

## 9. Testing gates

### PCCS tests

- Valid Platform CA and Processor CA certificates
- Missing, duplicate and wrong-length PPID
- Missing, duplicate and wrong-length PIID
- Reordered extensions
- Duplicate legacy extension fields
- Malformed ASN.1 tags and values, unknown SGX sub-OIDs, and invalid SGX Type, Configuration, or nested TCB fields
- Golden comparison proving legacy parser results remain byte-for-byte unchanged

### EVM tests

- V3 SGX, V4 SGX/TDX, V5 SGX/TD10/TD15
- Both Platform CA and Processor CA leaves
- On-chain V1 versus V2 output golden vectors
- Every old verification/program-registry selector is unavailable on AttestationV2, including owner calls
- Registration does not change the default; only strict IDs can be defaults; ID/mode mismatches reject; removed IDs cannot change mode when re-registered
- Identical `OutputV2` from on-chain and ZK paths for the same quote, collaterals, and verification timestamp
- V3 non-empty advisory IDs and preservation of advisory order
- Output/journal tests for the fixed `0x06`, statuses 8/9, permitted zero values, contiguous tails, canonical ABI encoding, and the 65,535-byte limit
- Separate V1 and V2 event decoding
- Legacy entrypoint regression tests
- Gas usage and deployed bytecode-size checks

### Rust/ZK tests

- Solidity/Rust cross-language serialization vectors
- Journal round trips for all quote-body types
- RISC Zero/SP1 real proof generation for production-enabled backends; separate local-only Pico proof testing is not a production release gate
- Verification using the production program identifiers and reused supported-network universal verifiers; Pico local proofs use a matching local verifier
- Fresh paired Docker builds for both modes on all three backends; fail if existing ELFs were reused
- Existing V1 ELF artifacts and program identifiers remain unchanged
- Rejection of a V1 journal through the V2 selector and vice versa
- Continued support for existing V1.0/V1.1 output parsing

## 10. Rollout sequence

1. Freeze the `OutputV2` and `JournalV2` wire formats and publish cross-language test vectors.
2. Selectively port the located staging guest projects and required support code, and document reproducible builds.
3. Merge and release the PCCS parser change.
4. Update the DCAP submodule pin.
5. Implement dual serializers and V2 methods across V3/V4/V5.
6. Build all three new ZK guests into isolated v2.0 artifact directories and record their hashes, program identifiers, source commits, and toolchain versions.
7. Update Rust/Go bindings, parsers and network registries.
8. Deploy to one canary testnet.
9. Read back the isolated Router/new helper configuration and run both legacy and V2 smoke tests without modifying shared configuration.
10. Roll out to the remaining testnets and allow a soak period.
11. Deploy mainnets in batches, verifying both paths after each batch.
12. Publish the V2 SDK/config release only after the corresponding chain deployment passes its smoke tests.
13. Keep legacy addresses and program identifiers available indefinitely unless a separate deprecation process is announced.

Development does not authorize live deployments, router updates, or SDK publication. These rollout operations require separate confirmation.

## 11. Rollback

The legacy entrypoint and quote-verifier mappings are never modified, so the primary rollback is:

1. Pause/stop advertising the isolated V2 instance; shared legacy Router/helper state needs no rollback.
2. Stop advertising the V2 entrypoint in the registry.
3. Freeze or remove only the affected V2 ZK route/program identifier if the issue is ZK-specific. Do not disable a shared universal verifier or remove V1 identifiers as part of a V2 rollback.

No legacy output migration or consumer rollback is required.

## 12. Appendix: Existing V1 wire formats

These are the formats currently deployed and consumed. All integers are big-endian. `quoteBodyType` determines the quote-body length: 1 = 384-byte SGX report, 2 = 584-byte TD 1.0 report, 3 = 648-byte TD 1.5 report. Empty advisory IDs append no trailing bytes. The internal fields of `quoteBody` are expanded in Sections 12.4.1–12.4.3; the ABI encoding of `advisoryIDs` is expanded in Section 12.4.4.

### 12.1 Solidity On-chain verified output (V1)

Returned by `verifyAndAttestOnChain` and embedded as the `verifiedOutput` segment of the V1 ZK journal. Produced by `serializeOutput` via `abi.encodePacked`.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | `quoteVersion` |
| 2 | 2 | `quoteBodyType` |
| 4 | 1 | `tcbStatus` |
| 5 | 6 | `fmspc` |
| 11 | 384/584/648 | `quoteBody` |
| 11 + body | variable | ABI-encoded `string[] advisoryIDs` |

The fixed prefix is 11 bytes. There is no version identifier; consumers must assume the layout.

### 12.2 ZK journal V1 with the full V1 output embedded (official guest)

The V1 journal envelope, committed by the guest program and verified by `verifyAndAttestWithZKProof`, is `outputLength(2) | variable verifiedOutput | timestamp(8) | 6 x 32-byte collateral hashes` (hash order: TCB Info content hash, QE Identity content hash, Root CA certificate hash, TCB Signing certificate hash, Root CA CRL hash, Platform/Processor PCK CRL hash). Because `verifiedOutput` is variable-length, the timestamp and collateral hash offsets are not compile-time constants; a parser must first decode `outputLength` to locate them.

This section expands the envelope with the official guest's verified output — the full V1 output of Section 12.1 — embedded. Journal-absolute offsets, with `bodyLen` in {384, 584, 648} and `advLen` the advisory encoding length (0 when empty). `outputLength = 11 + bodyLen + advLen`.

| Offset | Size | Field | Group |
| --- | --- | --- | --- |
| 0 | 2 | `outputLength` | envelope |
| 2 | 2 | `quoteVersion` | verifiedOutput |
| 4 | 2 | `quoteBodyType` | verifiedOutput |
| 6 | 1 | `tcbStatus` | verifiedOutput |
| 7 | 6 | `fmspc` | verifiedOutput |
| 13 | bodyLen | `quoteBody` | verifiedOutput |
| 13 + bodyLen | advLen | `advisoryIDs` | verifiedOutput |
| 2 + outputLength | 8 | `timestamp` | envelope |
| +8 | 32 | TCB Info content hash | envelope (collateral) |
| +40 | 32 | QE Identity content hash | envelope (collateral) |
| +72 | 32 | Root CA certificate hash | envelope (collateral) |
| +104 | 32 | TCB Signing certificate hash | envelope (collateral) |
| +136 | 32 | Root CA CRL hash | envelope (collateral) |
| +168 | 32 | PCK CRL hash | envelope (collateral) |

Total journal size: `2 + outputLength + 8 + 192`.

`Group` column legend: `verifiedOutput` rows are the segment the contract slices out and returns to the caller; `envelope` rows are journal framing used only for verification (length prefix, proof-committed timestamp, collateral hashes).

### 12.3 ZK journal V1 with a 131-byte compact output ("ATKJ" guest)

A downstream consumer (tee-workload-attestation) registers its own guest whose `verifiedOutput` is a fixed 131-byte compact output carrying hash commitments instead of the quote body and advisory IDs. `outputLength` is constant 131 and the total journal size is constant 333 bytes. Its `fullQuoteHash` and the current OutputV2 both use Keccak-256 of the raw quote, but their different wire formats and program families remain incompatible.

| Offset | Size | Field | Group |
| --- | --- | --- | --- |
| 0 | 2 | `outputLength` (= 131) | envelope |
| 2 | 2 | `quoteVersion` | verifiedOutput (compact) |
| 4 | 2 | `quoteBodyType` | verifiedOutput (compact) |
| 6 | 1 | `tcbStatus` | verifiedOutput (compact) |
| 7 | 6 | `fmspc` | verifiedOutput (compact) |
| 13 | 16 | format guard (all zero) | verifiedOutput (compact) |
| 29 | 4 | magic `0x41544b4a` ("ATKJ") | verifiedOutput (compact) |
| 33 | 2 | format type (= 1) | verifiedOutput (compact) |
| 35 | 2 | format version (= 1) | verifiedOutput (compact) |
| 37 | 32 | `fullQuoteHash` | verifiedOutput (compact) |
| 69 | 32 | `quoteBodyHash` | verifiedOutput (compact) |
| 101 | 32 | `advisoryIdsHash` | verifiedOutput (compact) |
| 133 | 8 | `timestamp` | envelope |
| 141 | 32 | TCB Info content hash | envelope (collateral) |
| 173 | 32 | QE Identity content hash | envelope (collateral) |
| 205 | 32 | Root CA certificate hash | envelope (collateral) |
| 237 | 32 | TCB Signing certificate hash | envelope (collateral) |
| 269 | 32 | Root CA CRL hash | envelope (collateral) |
| 301 | 32 | PCK CRL hash | envelope (collateral) |

Note: this compact format is defined by the downstream guest, not by this repository; the DCAP contract is agnostic to the `verifiedOutput` content and only validates the proof, collateral hashes, and timestamp. The constant offsets at 133+ are a side effect of the fixed 131-byte output, not a property of the V1 envelope itself.

### 12.4 Field expansions

The tables below expand the variable-length fields referenced by the wire formats above; they are field-level details, not standalone formats.

#### 12.4.1 `quoteBody` — Type 1: SGX Enclave Report Body (384 bytes)

Body-relative offsets. Multi-byte integers inside the report body are **little-endian** (Intel convention), unlike the big-endian outer prefix. Source: `rust-crates/libraries/dcap-rs/src/types/report.rs` (`EnclaveReportBody`), matching `sgx_report.h` in linux-sgx.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 16 | `cpusvn` (CPU Security Version) |
| 16 | 4 | `misc_select` (LE u32) |
| 20 | 12 | reserved1 |
| 32 | 16 | `isvextprodid` (extended product ID) |
| 48 | 16 | `attributes` (enclave attributes) |
| 64 | 32 | `mrenclave` (enclave measurement) |
| 96 | 32 | reserved2 |
| 128 | 32 | `mrsigner` (signer measurement) |
| 160 | 32 | reserved3 |
| 192 | 64 | `configid` |
| 256 | 2 | `isvprodid` (LE u16) |
| 258 | 2 | `isvsvn` (LE u16) |
| 260 | 2 | `configsvn` (LE u16) |
| 262 | 42 | reserved4 |
| 304 | 16 | `isv_family_id` |
| 320 | 64 | `report_data` (user report data) |

#### 12.4.2 `quoteBody` — Type 2: TD 1.0 Report Body (584 bytes)

Body-relative offsets. Source: `Td10ReportBody` in the same file.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 16 | `tee_tcb_svn` (TDX module TCB) |
| 16 | 48 | `mrseam` (TDX module measurement) |
| 64 | 48 | `mrsignerseam` (TDX module signer measurement) |
| 112 | 8 | `seam_attributes` |
| 120 | 8 | `td_attributes` |
| 128 | 8 | `xfam` (extended features available mask) |
| 136 | 48 | `mrtd` (initial TD contents measurement) |
| 184 | 48 | `mrconfigid` |
| 232 | 48 | `mrowner` |
| 280 | 48 | `mrownerconfig` |
| 328 | 48 | `rtmr0` |
| 376 | 48 | `rtmr1` |
| 424 | 48 | `rtmr2` |
| 472 | 48 | `rtmr3` |
| 520 | 64 | `report_data` (user report data) |

#### 12.4.3 `quoteBody` — Type 3: TD 1.5 Report Body (648 bytes)

The TD 1.5 body is the full 584-byte TD 1.0 body (offsets 0–583 identical to Section 12.4.2) followed by:

| Offset | Size | Field |
| --- | --- | --- |
| 584 | 16 | `tee_tcb_svn2` (current TCB after TD-preserving update) |
| 600 | 48 | `mr_service_td` (migration TD measurement) |

#### 12.4.4 `advisoryIDs` — ABI-encoded `string[]`

When non-empty, the tail of the output is exactly `abi.encode(string[])`:

| Offset (relative to advisory start) | Size | Field |
| --- | --- | --- |
| 0 | 32 | offset to array data (= `0x20`) |
| 32 | 32 | array length `n` |
| 64 | 32 × n | per-element offsets (relative to the element-offset table immediately after the array-length word) |
| 64 + 32n | variable | per-element payloads: 32-byte string length + UTF-8 bytes right-padded with zeros to a 32-byte multiple |

All ABI words are big-endian by ABI convention. When `n` advisory IDs are present, each payload occupies `32 + ceil(len/32) × 32` bytes. When the list is empty, **no bytes are appended at all** (the parser infers "empty" from the absence of trailing bytes rather than decoding an empty ABI array).
