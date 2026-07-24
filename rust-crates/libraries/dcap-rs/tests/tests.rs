mod common;

use common::*;
use dcap_rs::{
    DcapVerificationPolicy, types::quote::Quote, verify_dcap_quote, verify_dcap_quote_with_policy,
};

#[test]
fn parse_v3_quote() {
    let quote_hex = include_str!("../../../samples/quotev3.hex");
    let quote_bytes = hex::decode(quote_hex.trim()).unwrap();
    let quote = Quote::read(&mut quote_bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[test]
fn parse_v4_quote() {
    let quote_hex = include_str!("../../../samples/quotev4.hex");
    let quote_bytes = hex::decode(quote_hex.trim()).unwrap();
    let quote = Quote::read(&mut quote_bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[test]
fn parse_v5_quote() {
    let bytes = include_bytes!("../../../samples/quotev5.dat");
    let quote = Quote::read(&mut bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[tokio::test]
async fn e2e_v3_quote() {
    let (collateral, quote) = v3_quote_data().await;
    verify_dcap_quote(test_v3_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
}

#[tokio::test]
async fn e2e_v4_quote() {
    let (collateral, quote) = v4_quote_data().await;
    verify_dcap_quote(test_v4_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
}

#[tokio::test]
async fn e2e_v4_quote_rejects_root_crl_as_pck_crl() {
    let (mut collateral, quote) = v4_quote_data().await;
    collateral.pck_crl = collateral.root_ca_crl.clone();
    let error = verify_dcap_quote(test_v4_time(), collateral, quote)
        .expect_err("the root CA CRL must not cover a PCK certificate");
    assert!(
        format!("{error:#}").contains("no certificate revocation list for issuer"),
        "{error:#}"
    );
}

#[tokio::test]
async fn e2e_v4_quote_rejects_expired_crl() {
    let (collateral, quote) = v4_quote_data().await;
    let expired_at = collateral
        .pck_crl
        .tbs_cert_list
        .next_update
        .expect("Intel PCK CRL should have nextUpdate")
        .to_system_time();
    let error = verify_dcap_quote(expired_at, collateral, quote)
        .expect_err("a CRL must not be accepted at or after nextUpdate");
    assert!(
        format!("{error:#}").contains("certificate revocation list is not valid"),
        "{error:#}"
    );
}

#[tokio::test]
async fn e2e_v5_quote() {
    let (collateral, quote) = v5_quote_data().await;
    let policy = DcapVerificationPolicy {
        allow_service_td: true,
        ..DcapVerificationPolicy::production()
    };
    let output = verify_dcap_quote_with_policy(test_v5_time(), collateral, quote, &policy)
        .expect("certificate chain integrity should succeed when service TDs are allowed");
    println!("{:?}", output);
}
