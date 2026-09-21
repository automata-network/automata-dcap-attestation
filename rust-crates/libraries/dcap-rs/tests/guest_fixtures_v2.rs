#[path = "support/v2_fixture.rs"]
mod fixture;
#[path = "support/v2_negative_cases.rs"]
mod negative_cases;

use alloy_sol_types::SolType;
use dcap_rs::types::VerifiedOutputV2;
use dcap_rs::types::collateral::Collateral;
use dcap_rs::v2::verify_dcap_quote_v2_with_min_check;
use dcap_rs::v2::verify_guest_input_v2;
use dcap_rs::v2::verify_guest_input_v2_minimal;
use fixture::{GuestInput, V2Fixture, hex_bytes};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn both_modes_preserve_authentication_and_match_for_production_quotes() {
    for raw in FIXTURES.into_iter().chain(ATA_FIXTURES) {
        let fixture: V2Fixture = serde_json::from_str(raw).unwrap();
        let input = fixture.rebuild_input().unwrap();
        let (collateral, quote, timestamp) = GuestInput::abi_decode_params(&input).unwrap();
        let collateral = Collateral::sol_abi_decode(&collateral).unwrap();
        for min_check in [false, true] {
            let output = verify_dcap_quote_v2_with_min_check(
                UNIX_EPOCH + Duration::from_secs(timestamp),
                &collateral,
                &quote,
                min_check,
            )
            .unwrap();
            assert_eq!(
                output.to_vec().unwrap(),
                verify_guest_input_v2(&input).unwrap()
            );
            assert_eq!(
                output.full_quote_hash,
                alloy::primitives::keccak256(&quote).0
            );
            for (name, mutation) in negative_cases::negative_inputs(&input).unwrap() {
                let (collateral, quote, timestamp) =
                    GuestInput::abi_decode_params(&mutation).unwrap();
                let collateral = Collateral::sol_abi_decode(&collateral).unwrap();
                assert!(
                    verify_dcap_quote_v2_with_min_check(
                        UNIX_EPOCH + Duration::from_secs(timestamp),
                        &collateral,
                        &quote,
                        min_check
                    )
                    .is_err(),
                    "mode {min_check}: accepted {name}"
                );
            }
        }
    }
}

const FIXTURES: [&str; 3] = [
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v3.json"),
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v4.json"),
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v5.json"),
];

const ATA_FIXTURES: [&str; 2] = [
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/ata-sgx-v3.json"),
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/ata-tdx-v4.json"),
];

/// Signed Alibaba V5 quote with a non-zero MR_SERVICE_TD: the production-policy
/// cell where strict must reject and minimal must accept the same input.
const POLICY_FIXTURE: &str =
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/alibaba-v5.json");

#[test]
fn alibaba_v5_strict_rejects_minimal_accepts_with_frozen_journal() {
    let fixture: V2Fixture = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let input = fixture.rebuild_input().unwrap();
    let (collateral, quote, timestamp) = GuestInput::abi_decode_params(&input).unwrap();
    let collateral = Collateral::sol_abi_decode(&collateral).unwrap();
    let strict = verify_dcap_quote_v2_with_min_check(
        UNIX_EPOCH + Duration::from_secs(timestamp),
        &collateral,
        &quote,
        false,
    )
    .unwrap_err();
    assert!(
        strict.to_string().contains("migration service TD"),
        "unexpected strict rejection: {strict}"
    );
    let minimal = verify_dcap_quote_v2_with_min_check(
        UNIX_EPOCH + Duration::from_secs(timestamp),
        &collateral,
        &quote,
        true,
    )
    .unwrap();
    assert_eq!(minimal.to_vec().unwrap(), verify_guest_input_v2_minimal(&input).unwrap());
    assert_eq!(hex_bytes(&minimal.to_vec().unwrap()), fixture.expected_journal);
    // The same input stays frozen: the strict guest path keeps rejecting it and
    // every collateral/signature mutation stays rejected in both modes.
    assert!(verify_guest_input_v2(&input).is_err());
    for (name, mutation) in negative_cases::negative_inputs(&input).unwrap() {
        let (collateral, quote, timestamp) = GuestInput::abi_decode_params(&mutation).unwrap();
        let collateral = Collateral::sol_abi_decode(&collateral).unwrap();
        for min_check in [false, true] {
            assert!(
                verify_dcap_quote_v2_with_min_check(
                    UNIX_EPOCH + Duration::from_secs(timestamp),
                    &collateral,
                    &quote,
                    min_check
                )
                .is_err(),
                "mode {min_check}: accepted {name}"
            );
        }
    }
}

#[test]
fn public_ata_quotes_match_frozen_journals_and_reject_eight_mutations_each() {
    for raw in ATA_FIXTURES {
        let fixture: V2Fixture = serde_json::from_str(raw).unwrap();
        let input = fixture.rebuild_input().unwrap();
        let journal = verify_guest_input_v2(&input).unwrap();
        assert_eq!(hex_bytes(&journal), fixture.expected_journal);
        let output = VerifiedOutputV2::from_bytes(&journal).unwrap();
        assert_eq!(output.quote_version, fixture.quote_version);
        assert_eq!(
            output.quote_body_type,
            if fixture.quote_version == 3 { 1 } else { 2 }
        );
        assert_eq!(
            (output.format_major_version, output.format_minor_version),
            (2, 1)
        );
        assert_eq!(output.timestamp, fixture.verification_timestamp);
        assert!(output.piid_present);
        assert_eq!(
            output.full_quote_hash.to_vec(),
            alloy::primitives::keccak256(fixture::unhex(&fixture.quote).unwrap()).to_vec()
        );
        let mutations = negative_cases::negative_inputs(&input).unwrap();
        assert_eq!(mutations.len(), 8);
        for (name, input) in mutations {
            assert!(verify_guest_input_v2(&input).is_err(), "accepted {name}");
        }
    }
}

#[test]
fn supplied_tdx_padding_is_preserved_and_rejected_not_silently_normalized() {
    let fixture: V2Fixture = serde_json::from_str(ATA_FIXTURES[1]).unwrap();
    let padded = fixture::unhex(
        include_str!("../../../../evm/forge-test/assets/v2/quotes/ata-tdx-v4.hex").trim(),
    )
    .unwrap();
    let extracted = fixture::unhex(
        include_str!("../../../../evm/forge-test/assets/v2/quotes/ata-tdx-v4-extracted.hex").trim(),
    )
    .unwrap();
    assert_eq!(padded.len(), 8000);
    assert_eq!(extracted.len(), 4935);
    assert_eq!(&padded[..4935], extracted);
    assert!(padded[4935..].iter().all(|b| *b == 0));
    assert_eq!(hex_bytes(&extracted), fixture.quote);
    let (collateral, _, timestamp) =
        GuestInput::abi_decode_params(&fixture.rebuild_input().unwrap()).unwrap();
    let invalid = GuestInput::abi_encode_params(&(collateral, padded, timestamp));
    assert_eq!(
        verify_guest_input_v2(&invalid).unwrap_err().to_string(),
        "trailing bytes after quote"
    );
    let sgx: V2Fixture = serde_json::from_str(ATA_FIXTURES[0]).unwrap();
    assert_eq!(
        fixture::unhex(&sgx.quote).unwrap(),
        fixture::unhex(
            include_str!("../../../../evm/forge-test/assets/v2/quotes/ata-sgx-v3.hex").trim()
        )
        .unwrap()
    );
}

#[test]
fn frozen_inputs_rebuild_without_network_and_match_journals() {
    for raw in FIXTURES {
        let fixture: V2Fixture = serde_json::from_str(raw).unwrap();
        let input = fixture.rebuild_input().unwrap();
        let journal = verify_guest_input_v2(&input).unwrap();
        assert_eq!(hex_bytes(&journal), fixture.expected_journal);
        let output = VerifiedOutputV2::from_bytes(&journal).unwrap();
        assert_eq!(output.quote_version, fixture.quote_version);
        assert_eq!(
            (output.format_major_version, output.format_minor_version),
            (2, 1)
        );
        assert_eq!(output.timestamp, fixture.verification_timestamp);
        assert!(output.piid_present);
        if fixture.quote_version == 5 {
            assert_eq!(output.quote_body_type, 3);
            let raw = fixture::unhex(&fixture.quote).unwrap();
            let parsed = dcap_rs::types::quote::Quote::read(&mut raw.as_slice()).unwrap();
            assert_eq!(parsed.body.as_bytes().len(), 648);
            assert_eq!(&parsed.body.as_bytes()[600..648], &[0; 48]);
            assert_eq!(
                output.quote_body_hash,
                alloy::primitives::keccak256(parsed.body.as_bytes()).0
            );
        } else {
            let reference = if fixture.quote_version == 3 {
                include_str!("../../../../evm/forge-test/assets/v2/verified-v3.hex")
            } else {
                include_str!("../../../../evm/forge-test/assets/v2/verified-v4.hex")
            };
            assert_eq!(journal, hex::decode(reference.trim()).unwrap());
        }
    }
}

#[test]
fn frozen_inputs_reject_signed_body_mutations_and_pre_validity_times() {
    for raw in FIXTURES {
        let fixture: V2Fixture = serde_json::from_str(raw).unwrap();
        let (collateral, quote, timestamp) =
            GuestInput::abi_decode_params(&fixture.rebuild_input().unwrap()).unwrap();
        let mut tampered = quote.to_vec();
        tampered[80] ^= 1;
        let input = GuestInput::abi_encode_params(&(collateral.clone(), tampered, timestamp));
        assert!(verify_guest_input_v2(&input).is_err());
        let input = GuestInput::abi_encode_params(&(collateral, quote, 0u64));
        assert!(verify_guest_input_v2(&input).is_err());
    }
}
