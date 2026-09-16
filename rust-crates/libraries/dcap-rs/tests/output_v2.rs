use dcap_rs::{types::collateral::Collateral, verify_dcap_quote_v2};
use std::time::{Duration, UNIX_EPOCH};

fn solidity_hex(source: &str, name: &str) -> Vec<u8> {
    let tail = source
        .split(&format!("bytes constant {name} ="))
        .nth(1)
        .unwrap();
    hex::decode(
        tail.split("hex\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn real_tdx15_v2_output() {
    const SETUP: &str = include_str!("../../../../evm/forge-test/utils/PCCSSetupBase.sol");
    const TEST: &str = include_str!("../../../../evm/forge-test/QuoteV5Test.s.sol");
    let chain = format!(
        "{}{}",
        pem::encode(&pem::Pem::new(
            "CERTIFICATE",
            solidity_hex(SETUP, "signingDer")
        )),
        pem::encode(&pem::Pem::new(
            "CERTIFICATE",
            solidity_hex(SETUP, "rootCaDer")
        ))
    );
    let collateral = Collateral::new(
        &solidity_hex(SETUP, "rootCrlDer"),
        &solidity_hex(TEST, "platformCrlDer"),
        chain.as_bytes(),
        include_str!("../../../../evm/forge-test/assets/0625/tcbinfov3_90C06F000000.json"),
        include_str!("../../../../evm/forge-test/assets/0625/qe_td.json"),
    )
    .unwrap();
    let quote = include_bytes!("../../../../evm/forge-test/assets/quotes/alibaba_quote_5.dat");
    // Main's production policy rejects this signed migration-enabled fixture.
    let error = verify_dcap_quote_v2(
        UNIX_EPOCH + Duration::from_secs(1749945600),
        &collateral,
        quote,
    )
    .unwrap_err();
    assert!(error.to_string().contains("migration service TD"));
    let time = UNIX_EPOCH + Duration::from_secs(1749945600);
    let output =
        dcap_rs::v2::verify_dcap_quote_v2_with_min_check(time, &collateral, quote, true).unwrap();
    assert_eq!(
        output.full_quote_hash,
        alloy::primitives::keccak256(quote).0
    );
    assert_ne!(&output.quote_body[600..648], &[0u8; 48]);
    let input = dcap_rs::v2::encode_guest_input_v2(&collateral, quote, 1749945600).unwrap();
    assert_eq!(
        dcap_rs::v2::verify_guest_input_v2(&input).unwrap(),
        output.to_vec().unwrap()
    );
}

#[test]
fn shared_wire_vectors() {
    use dcap_rs::types::VerifiedOutputV2;
    for raw in [
        include_str!("../../../../evm/forge-test/assets/v2/sgx-empty.hex"),
        include_str!("../../../../evm/forge-test/assets/v2/tdx10-advisories.hex"),
        include_str!("../../../../evm/forge-test/assets/v2/tdx15-relaunch.hex"),
    ] {
        let data = hex::decode(raw.trim()).unwrap();
        let out = VerifiedOutputV2::from_bytes(&data).unwrap();
        assert_eq!(out.timestamp, 0x0102030405060708);
        assert_eq!(out.ppid, [0; 16]);
        assert_eq!(out.to_vec().unwrap(), data);
    }
}

#[test]
fn real_v3_v4_v2_outputs() {
    const SETUP: &str = include_str!("../../../../evm/forge-test/utils/PCCSSetupBase.sol");
    const TEST: &str =
        include_str!("../../../../evm/forge-test/AutomataDcapOnChainAttestationTest.t.sol");
    let chain = format!(
        "{}{}",
        pem::encode(&pem::Pem::new(
            "CERTIFICATE",
            solidity_hex(SETUP, "signingDer")
        )),
        pem::encode(&pem::Pem::new(
            "CERTIFICATE",
            solidity_hex(SETUP, "rootCaDer")
        ))
    );
    for (v, time, raw, tcb, qe, crl) in [
        (
            3,
            1755236700,
            include_str!("../../../../evm/forge-test/assets/v2/quote-v3.hex"),
            include_str!("../../../../evm/forge-test/assets/0825/sgx_tcbinfov3_00606a000000.json"),
            include_str!("../../../../evm/forge-test/assets/0825/sgx_qeidentity_v4.json"),
            include_bytes!("../../../../evm/forge-test/assets/0825/platform_crl.der").to_vec(),
        ),
        (
            4,
            1749095100,
            include_str!("../../../../evm/forge-test/assets/v2/quote-v4.hex"),
            include_str!("../../../../evm/forge-test/assets/0625/tcbinfov3_00806f050000.json"),
            include_str!("../../../../evm/forge-test/assets/0625/qe_td.json"),
            solidity_hex(TEST, "platformCrlDer"),
        ),
    ] {
        let collateral = Collateral::new(
            &solidity_hex(SETUP, "rootCrlDer"),
            &crl,
            chain.as_bytes(),
            tcb,
            qe,
        )
        .unwrap();
        let quote = hex::decode(raw.trim()).unwrap();
        let out = verify_dcap_quote_v2(UNIX_EPOCH + Duration::from_secs(time), &collateral, &quote)
            .unwrap();
        assert_eq!(out.quote_version, v);
        let expected = if v == 3 {
            include_str!("../../../../evm/forge-test/assets/v2/verified-v3.hex")
        } else {
            include_str!("../../../../evm/forge-test/assets/v2/verified-v4.hex")
        };
        assert_eq!(out.to_vec().unwrap(), hex::decode(expected.trim()).unwrap());
    }
}
