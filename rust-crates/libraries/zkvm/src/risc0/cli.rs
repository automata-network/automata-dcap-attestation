use alloy::providers::Provider;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::common::{
    display_proof_result, prepare_guest_input, write_proof_artifact, ProofArtifact, ZkVmProver,
};

use super::{
    config::{BoundlessConfig, ProvingStrategy, Risc0Config},
    prover::Risc0Prover,
};

/// Available subcommands for the RISC Zero zkVM integration.
#[derive(Subcommand, Debug, Clone)]
pub enum Risc0Command {
    /// Fetch proof from RISC Zero (via Bonsai or Boundless).
    Prove(Risc0ProveArgs),

    /// Compute the Image ID of the guest application.
    ImageId,
}

/// Arguments for running the RISC Zero proving flow.
#[derive(Args, Debug, Clone)]
pub struct Risc0ProveArgs {
    #[command(subcommand)]
    pub strategy: ProveStrategy,
}

/// Proving strategy subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum ProveStrategy {
    /// Prove using Bonsai
    Bonsai(BonsaiProveArgs),

    /// Prove using Boundless
    Boundless(BoundlessProveArgs),
}

/// Arguments for Bonsai proving
#[derive(Args, Debug, Clone)]
pub struct BonsaiProveArgs {
    /// Bonsai API URL (can be set via BONSAI_API_URL env var)
    #[arg(long = "api-url", env = "BONSAI_API_URL")]
    pub api_url: Option<String>,

    /// Bonsai API Key (can be set via BONSAI_API_KEY env var)
    #[arg(long = "api-key", env = "BONSAI_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Optional path to write proof artifact as JSON
    #[arg(long, value_name = "PATH")]
    pub output_path: Option<PathBuf>,
}

/// Arguments for Boundless proving
#[derive(Args, Debug, Clone)]
pub struct BoundlessProveArgs {
    /// RPC URL for Boundless
    #[arg(long = "boundless-rpc-url", env = "BOUNDLESS_RPC_URL")]
    pub boundless_rpc_url: Option<String>,

    /// Wallet private key for Boundless
    #[arg(
        long = "boundless-private-key",
        env = "BOUNDLESS_PRIVATE_KEY",
        hide_env_values = true
    )]
    pub boundless_private_key: Option<String>,

    /// URL to the guest ELF program (optional)
    #[arg(long = "program-url", env = "BOUNDLESS_PROGRAM_URL")]
    pub program_url: Option<String>,

    /// Proof type (groth16 or merkle)
    #[arg(long = "proof-type", value_enum, default_value = "groth16")]
    pub proof_type: super::config::BoundlessProofType,

    /// Minimum price in wei (optional)
    #[arg(long = "min-price")]
    pub min_price: Option<u128>,

    /// Maximum price in wei (optional)
    #[arg(long = "max-price")]
    pub max_price: Option<u128>,

    /// Timeout in seconds (optional)
    #[arg(long = "timeout")]
    pub timeout: Option<u32>,

    /// Ramp up period in seconds (optional)
    #[arg(long = "ramp-up-period")]
    pub ramp_up_period: Option<u32>,

    /// Optional path to write proof artifact as JSON
    #[arg(long, value_name = "PATH")]
    pub output_path: Option<PathBuf>,
}

/// Execute a RISC Zero subcommand using the shared library implementation.
pub async fn run<P: Provider>(
    command: Risc0Command,
    quote_bytes: Option<Vec<u8>>,
    provider: &P,
    version: automata_dcap_utils::Version,
    tcb_eval_num: Option<u32>,
) -> Result<()> {
    match command {
        Risc0Command::Prove(args) => {
            let quote_bytes = quote_bytes.context("Quote bytes must be provided for proving")?;
            prove(args, quote_bytes, provider, version, tcb_eval_num).await?
        },
        Risc0Command::ImageId => print_image_id(version)?,
    }

    println!("Job completed!");

    Ok(())
}

async fn prove<P: Provider>(
    args: Risc0ProveArgs,
    quote_bytes: Vec<u8>,
    provider: &P,
    version: automata_dcap_utils::Version,
    tcb_eval_num: Option<u32>,
) -> Result<()> {
    // Step 1: Prepare version-aware guest input (DCAP workflow)
    let input_bytes = prepare_guest_input(provider, Some(version), &quote_bytes, tcb_eval_num).await?;

    // Step 2: Create version-aware prover
    let prover = Risc0Prover::new(version)?;

    // Step 3: Build RISC0 configuration based on proving strategy and extract output_path
    let (config, output_path) = match args.strategy {
        ProveStrategy::Bonsai(bonsai_args) => {
            let bonsai_config = super::config::BonsaiConfig {
                api_url: bonsai_args.api_url,
                api_key: bonsai_args.api_key,
            };

            let config = Risc0Config {
                proving_strategy: ProvingStrategy::Bonsai,
                bonsai: Some(bonsai_config),
                boundless: None,
            };

            (config, bonsai_args.output_path)
        }
        ProveStrategy::Boundless(boundless_args) => {
            let boundless_config = BoundlessConfig {
                rpc_url: boundless_args.boundless_rpc_url,
                private_key: boundless_args.boundless_private_key,
                program_url: boundless_args.program_url,
                proof_type: boundless_args.proof_type,
                min_price: boundless_args.min_price,
                max_price: boundless_args.max_price,
                timeout: boundless_args.timeout,
                ramp_up_period: boundless_args.ramp_up_period,
            };

            let config = Risc0Config {
                proving_strategy: ProvingStrategy::Boundless,
                bonsai: None,
                boundless: Some(boundless_config),
            };

            (config, boundless_args.output_path)
        }
    };

    // Step 4: Generate proof using RISC0 prover
    let (journal, seal) = prover.prove(&config, &input_bytes)
        .await
        .context("RISC0 proving failed")?;

    // Step 5: Display proof result
    display_proof_result(&journal, &seal, "Seal", version)?;

    // Step 6: Write proof artifact if output path is provided
    if let Some(output_path) = output_path {
        let program_id = prover.program_identifier()?;
        let circuit_version = Risc0Prover::circuit_version();
        let artifact = ProofArtifact {
            zkvm: "risc0".to_string(),
            program_id,
            circuit_version,
            journal: hex::encode(&journal),
            proof: hex::encode(&seal),
        };
        write_proof_artifact(&output_path, &artifact)?;
    }

    Ok(())
}

fn print_image_id(version: automata_dcap_utils::Version) -> Result<()> {
    let prover = Risc0Prover::new(version)?;
    let image_id = prover.program_identifier()?;
    println!("ImageID: {}", image_id);
    Ok(())
}
