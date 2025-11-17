pub mod cloud_providers;
pub mod contracts;
pub mod helper;
pub mod pccs_types;

pub use helper::{
    sgx_ql_get_quote_config, sgx_ql_get_quote_verification_collateral, sgx_ql_get_qve_identity,
    sgx_ql_get_root_ca_crl, tdx_ql_get_quote_verification_collateral, upload_missing_collaterals,
};
pub use pccs_reader_rs::{
    CollateralError, Collaterals, MissingCollateral, MissingCollateralReport,
};

use automata_dcap_network_registry::Network;

/// Determine which collateral data is missing for the provided DCAP quote.
/// Returns Ok(()) if all collaterals are present and valid.
/// Returns Err(CollateralError) which can be Missing(report) or Validation(msg).
pub async fn detect_missing_collateral(
    network: &Network,
    quote: &[u8],
    tcb_eval_num: Option<u32>,
) -> Result<(), CollateralError> {
    // Create provider from network for pccs-reader (read-only, no private key needed)
    let provider = network
        .create_provider(None, None)
        .map_err(|e| CollateralError::Validation(format!("Failed to create provider: {}", e)))?;
    pccs_reader_rs::find_missing_collaterals_from_quote(
        &provider,
        Some(network.version),
        quote,
        false,
        tcb_eval_num,
    )
    .await
    .map(|_collaterals| ())
}
