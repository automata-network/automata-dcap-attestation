mod common;

use common::*;
use dcap_rs::{types::quote::Quote, verify_dcap_quote};

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
async fn e2e_v5_quote() {
    let (collateral, quote) = v5_quote_data().await;
    let output = verify_dcap_quote(test_v5_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
    println!("{:?}", output);
}
