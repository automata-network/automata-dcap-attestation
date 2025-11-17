use alloy::providers::Provider;
use anyhow::Result;
use automata_dcap_network_registry::Network;
use automata_dcap_utils::Version;

use super::{inputs::generate_input, quote::QuoteMetadata};

/// Prepare guest input for zkVM proving by fetching collaterals for the provided quote.
///
/// This function performs the DCAP-specific workflow that is common across all zkVMs:
/// 1. Parse and log quote metadata
/// 2. Fetch missing collaterals from PCCS
/// 3. Generate version-aware serialized input bytes
///
/// # Arguments
/// * `quote_bytes` - The quote bytes to process
/// * `provider` - The alloy provider to use for fetching collaterals
/// * `tcb_eval_num` - Optional TCB evaluation number for versioned DAO resolution
/// * `deployment_version` - Optional deployment version
///
/// # Returns
/// * Serialized input bytes ready to be passed to the zkVM prover
///
/// # Errors
/// Returns error if quote parsing, collateral fetching, or serialization fails
pub async fn prepare_guest_input<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    quote_bytes: &[u8],
    tcb_eval_num: Option<u32>,
) -> Result<Vec<u8>> {
    // Step 0: Use provided quote bytes
    println!("Begin reading quote...");
    let quote = quote_bytes.to_vec();

    // Parse and log quote metadata
    let metadata = QuoteMetadata::from_quote(&quote)?;
    metadata.log_info();
    let quote_version = metadata.version;

    if deployment_version.unwrap() == Version::V1_0 {
        if quote_version != 3 && quote_version != 4 {
            return Err(anyhow::anyhow!(
                "Incompatible quote version for DCAP v1.0: expected version 3 or 4, got version {}",
                quote_version
            ));
        }
    }

    // Step 1: Fetch collaterals using pccs-reader-rs
    println!("Quote read successfully. Begin fetching collaterals using pccs-reader-rs...");

    // Derive network from provider
    let network = Network::from_provider(provider, deployment_version).await?;

    println!(
        "Fetching collaterals from network: {} (chain_id: {})",
        network.display_name, network.chain_id
    );
    let collaterals = pccs_reader_rs::find_missing_collaterals_from_quote(
        provider,
        deployment_version,
        &quote,
        false,
        tcb_eval_num,
    )
    .await
    .map_err(|e| match e {
        pccs_reader_rs::CollateralError::Missing(report) => {
            anyhow::anyhow!(
                "Failed to fetch all required collaterals from PCCS:\n{}",
                report
            )
        }
        pccs_reader_rs::CollateralError::Validation(msg) => {
            anyhow::anyhow!("Quote validation error: {}", msg)
        }
    })?;
    log::debug!("Fetched collaterals: {:?}", collaterals);

    println!("All collaterals fetched successfully!");

    // Step 2: Generate version-aware input bytes with current timestamp
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let version = deployment_version.unwrap_or(Version::V1_1);
    let input_bytes = generate_input(&quote, &collaterals, current_time, version)?;

    Ok(input_bytes)
}
