#[path = "support/v2_fixture.rs"]
mod fixture;

use alloy_sol_types::SolType;
use dcap_rs::types::VerifiedOutputV2;
use dcap_rs::v2::verify_guest_input_v2;
use fixture::{GuestInput, V2Fixture, hex_bytes};

const FIXTURES: [&str; 3] = [
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v3.json"),
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v4.json"),
    include_str!("../../../../evm/forge-test/assets/v2/fixtures/v5.json"),
];

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
            assert_eq!(output.quote_body.len(), 648);
            assert_eq!(&output.quote_body[600..648], &[0; 48]);
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
