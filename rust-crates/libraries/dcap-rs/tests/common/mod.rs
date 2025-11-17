use std::time::SystemTime;

use alloy::providers::Provider;
use automata_dcap_network_registry::Network;
use pccs_reader_rs::{find_missing_collaterals_from_quote, tcb_pem};

use dcap_rs::{
    types::{collateral::Collateral, quote::Quote},
};

/// Creates a provider for the default PCCS network
fn get_default_provider() -> impl Provider {
    let provider =
        Network::create_provider(&Network::default_network(None).unwrap(), None, None)
            .expect("Failed to get provider from default network");
    provider
}

/// Fetches collaterals from PCCS for a given quote
async fn fetch_collaterals_from_pccs(quote_bytes: &[u8]) -> Collateral {
    let provider = get_default_provider();

    let pccs_collaterals = find_missing_collaterals_from_quote(
        &provider,
        None,
        quote_bytes,
        false,
        None
    )
    .await
    .expect("Failed to fetch collaterals from PCCS");

    // Convert pccs-reader Collaterals to dcap-rs Collateral
    let pem_chain = tcb_pem::generate_tcb_issuer_chain_pem(
        &pccs_collaterals.tcb_signing_ca,
        &pccs_collaterals.root_ca,
    )
    .expect("Failed to generate PEM chain");

    Collateral::new(
        &pccs_collaterals.root_ca_crl,
        &pccs_collaterals.pck_crl,
        pem_chain.as_bytes(),
        &pccs_collaterals.tcb_info,
        &pccs_collaterals.qe_identity,
    )
    .expect("Failed to create Collateral from PCCS data")
}

pub async fn v3_quote_data() -> (Collateral, Quote<'static>) {
    // quotev3.hex is hex-encoded, so we need to decode it
    let quote_hex = include_str!("../../../../samples/quotev3.hex");
    let quote_bytes = hex::decode(quote_hex.trim()).expect("Failed to decode hex");

    // We need to leak the bytes to get 'static lifetime for Quote
    let quote_bytes_static: &'static [u8] = Box::leak(quote_bytes.into_boxed_slice());
    let quote = Quote::read(&mut quote_bytes_static.as_ref()).unwrap();

    let collateral = fetch_collaterals_from_pccs(quote_bytes_static).await;

    (collateral, quote)
}

pub async fn v4_quote_data() -> (Collateral, Quote<'static>) {
    // quotev4.hex is hex-encoded, so we need to decode it
    let quote_hex = include_str!("../../../../samples/quotev4.hex");
    let quote_bytes = hex::decode(quote_hex.trim()).expect("Failed to decode hex");

    // We need to leak the bytes to get 'static lifetime for Quote
    let quote_bytes_static: &'static [u8] = Box::leak(quote_bytes.into_boxed_slice());
    let quote = Quote::read(&mut quote_bytes_static.as_ref()).unwrap();

    let collateral = fetch_collaterals_from_pccs(quote_bytes_static).await;

    (collateral, quote)
}

pub async fn v5_quote_data() -> (Collateral, Quote<'static>) {
    // quotev5.dat is binary data, not hex-encoded
    let quote = include_bytes!("../../../../samples/quotev5.dat");
    let quote_parsed = Quote::read(&mut quote.as_slice()).unwrap();

    let collateral = fetch_collaterals_from_pccs(quote).await;

    (collateral, quote_parsed)
}

pub fn test_v3_time() -> SystemTime {
    // Use current time since we're fetching fresh collaterals from PCCS
    SystemTime::now()
}

pub fn test_v4_time() -> SystemTime {
    // Use current time since we're fetching fresh collaterals from PCCS
    SystemTime::now()
}

pub fn test_v5_time() -> SystemTime {
    // Use current time since we're fetching fresh collaterals from PCCS
    SystemTime::now()
}
