use alloy::providers::Provider;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::common::{
    display_proof_result, prepare_guest_input, write_proof_artifact, ProofArtifact, ZkVmProver,
};

use super::{
    config::{NetworkProverMode, ProofSystem, Sp1Config},
    prover::Sp1Prover,
};

/// Available subcommands for the SP1 zkVM integration.
#[derive(Subcommand, Debug, Clone)]
pub enum Sp1Command {
    /// Fetch proof from SP1.
    Prove(Sp1ProveArgs),

    /// Compute and display the verifying key (VK) of the guest program.
    VerifyingKey,
}

/// Arguments for running the SP1 proving flow.
#[derive(Args, Debug, Clone)]
pub struct Sp1ProveArgs {
    /// Proof system to use (Groth16 or Plonk)
    #[arg(
        short = 's',
        long = "proof-system",
        value_enum,
        default_value = "groth16"
    )]
    pub proof_system: ProofSystem,

    /// Network prover mode (hosted, reserved, or auction)
    #[arg(
        short = 'n',
        long = "network-prover-mode",
        value_enum,
        default_value = "auction"
    )]
    pub network_prover_mode: NetworkProverMode,

    /// SP1 Network Private Key
    #[arg(
        long = "sp1-private-key",
        env = "SP1_NETWORK_PRIVATE_KEY",
        hide_env_values = true
    )]
    pub sp1_private_key: String,

    /// Optional path to write proof artifact as JSON
    #[arg(long, value_name = "PATH")]
    pub output_path: Option<PathBuf>,
}

/// Execute an SP1 subcommand using the shared library implementation.
pub async fn run<P: Provider>(
    command: Sp1Command,
    quote_bytes: Option<Vec<u8>>,
    provider: &P,
    version: automata_dcap_utils::Version,
    tcb_eval_num: Option<u32>,
) -> Result<()> {
    match command {
        Sp1Command::Prove(args) => {
            let quote_bytes = quote_bytes.context("Quote bytes must be provided for proving")?;
            prove_cmd(args, quote_bytes, provider, version, tcb_eval_num).await?
        }
        Sp1Command::VerifyingKey => verifying_key_cmd(version)?,
    }

    println!("Job completed!");

    Ok(())
}

async fn prove_cmd<P: Provider>(
    args: Sp1ProveArgs,
    quote_bytes: Vec<u8>,
    provider: &P,
    version: automata_dcap_utils::Version,
    tcb_eval_num: Option<u32>,
) -> Result<()> {
    // Step 1: Prepare version-aware guest input (DCAP workflow)
    let input_bytes =
        prepare_guest_input(provider, Some(version), &quote_bytes, tcb_eval_num).await?;

    // Step 2: Create version-aware prover
    let prover = Sp1Prover::new(version)?;

    // Step 3: Build SP1 configuration
    let config = Sp1Config {
        proof_system: args.proof_system,
        network_mode: args.network_prover_mode,
        private_key: args.sp1_private_key,
        rpc_url: None,
    };

    // Step 4: Generate proof using SP1 prover
    let (journal, proof_bytes) = prover.prove(&config, &input_bytes)
        .await
        .context("SP1 proving failed")?;

    // Step 5: Display proof result
    display_proof_result(&journal, &proof_bytes, "Proof", version)?;

    // Step 6: Write proof artifact if output path is provided
    if let Some(output_path) = args.output_path {
        let program_id = prover.program_identifier()?;
        let circuit_version = Sp1Prover::circuit_version();
        let artifact = ProofArtifact {
            zkvm: "sp1".to_string(),
            program_id,
            circuit_version,
            journal: hex::encode(&journal),
            proof: hex::encode(&proof_bytes),
        };
        write_proof_artifact(&output_path, &artifact)?;
    }

    Ok(())
}

fn verifying_key_cmd(version: automata_dcap_utils::Version) -> Result<()> {
    let prover = Sp1Prover::new(version)?;
    let vk = prover.program_identifier()?;
    println!("VK: {}", vk);
    Ok(())
}
