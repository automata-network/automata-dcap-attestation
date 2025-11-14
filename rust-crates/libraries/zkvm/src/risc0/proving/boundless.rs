use anyhow::{Context, Error, Result};
use boundless_market::{
    alloy::{
        primitives::U256,
        providers::{Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
        transports::http::reqwest::Url,
    },
    client::Client,
    request_builder::OfferParams,
    storage::storage_provider_from_env,
    Deployment,
};
use std::time::Duration;

use super::super::config::BoundlessConfig;

/// Prove using Boundless network
pub async fn prove_with_boundless(
    elf: &'static [u8],
    input_bytes: &[u8],
    config: &BoundlessConfig,
) -> Result<Vec<u8>> {
    // Validate required config
    let rpc_url = config
        .rpc_url
        .as_ref()
        .context("--boundless-rpc-url or BOUNDLESS_RPC_URL is required for boundless strategy")?;
    let private_key_hex = config.private_key.as_ref().context(
        "--boundless-private-key or BOUNDLESS_PRIVATE_KEY is required for boundless strategy",
    )?;

    // Parse RPC URL
    let rpc_url_parsed: Url = rpc_url.parse().context("Invalid RPC URL format")?;

    // Get chain deployment
    let provider = ProviderBuilder::new().connect_http(rpc_url_parsed.clone());
    let chain_id = provider
        .get_chain_id()
        .await
        .context("Failed to retrieve chain ID")?;
    log::info!("Detected chain ID: {}", chain_id);

    let deployment = Deployment::from_chain_id(chain_id)
        .with_context(|| format!("No Boundless deployment found for chain ID {}", chain_id))?;

    // Parse private key
    let private_key_bytes = hex::decode(private_key_hex).context("Failed to decode private key")?;
    let private_key = PrivateKeySigner::from_slice(&private_key_bytes)
        .context("Failed to create signer from private key")?;

    // Get storage provider from environment
    let storage_provider = match storage_provider_from_env() {
        Ok(provider) => Some(provider),
        Err(e) => {
            return Err(
                Error::msg("boundless-error: Storage provider configuration is invalid: ")
                    .context(e),
            );
        }
    };

    // Build Boundless client
    let client = Client::builder()
        .with_rpc_url(rpc_url_parsed)
        .with_deployment(deployment)
        .with_storage_provider(storage_provider)
        .with_private_key(private_key)
        .build()
        .await?;

    // Build the proof request
    let mut request_builder = client.new_request().with_stdin(input_bytes);

    if let Some(program_url) = &config.program_url {
        request_builder = request_builder.with_program_url(program_url.as_str())?;
    } else {
        request_builder = request_builder.with_program(elf.to_vec());
    }

    // Set proof type (Groth16 or Merkle)
    if config.proof_type == super::super::config::BoundlessProofType::Groth16 {
        request_builder = request_builder.with_groth16_proof();
    }

    // Only set offer params if user provides them (Boundless handles defaults)
    if config.min_price.is_some()
        || config.max_price.is_some()
        || config.timeout.is_some()
        || config.ramp_up_period.is_some()
    {
        let mut offer_builder = OfferParams::builder();

        if let Some(min_price) = config.min_price {
            offer_builder.min_price(U256::from(min_price));
        }
        if let Some(max_price) = config.max_price {
            offer_builder.max_price(U256::from(max_price));
        }
        if let Some(timeout) = config.timeout {
            offer_builder.timeout(timeout);
        }
        if let Some(ramp_up_period) = config.ramp_up_period {
            offer_builder.ramp_up_period(ramp_up_period);
        }

        request_builder = request_builder.with_offer(offer_builder);
    }

    log::debug!("Request: {:?}", &request_builder);

    // Submit request to Boundless network
    log::info!("Submitting proof request to Boundless network...");
    let (request_id, expires_at) = client.submit_onchain(request_builder).await?;

    // Wait for the request to be fulfilled
    log::info!("Waiting for request {:x} to be fulfilled", request_id);
    let fulfillment = client
        .wait_for_request_fulfillment(
            request_id,
            Duration::from_secs(5), // check every 5 seconds
            expires_at,
        )
        .await?;
    log::info!("Request {:x} fulfilled", request_id);

    Ok(fulfillment.seal.to_vec())
}
