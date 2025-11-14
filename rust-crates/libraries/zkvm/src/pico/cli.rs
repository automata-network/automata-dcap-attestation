use alloy::providers::Provider;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::common::{
    display_proof_result, prepare_guest_input, write_proof_artifact, ProofArtifact, ZkVmProver,
};

use super::config::PicoConfig;
use super::prover::PicoProver;

/// Pico zkVM commands
#[derive(Subcommand, Debug)]
pub enum PicoCommand {
    /// Generate a proof for DCAP quote verification using Pico zkVM
    Prove(PicoProveArgs),

    /// Generate EVM contract inputs from proof artifacts
    GenerateEvmInputs(PicoGenerateEvmInputsArgs),

    /// Display the program identifier (vkey hash) for on-chain verification
    ProgramId,
}

#[derive(Args, Debug)]
pub struct PicoProveArgs {
    /// Optional: Path to directory containing EVM proof artifacts (vm_pk, vm_vk, constraints.json)
    /// If not provided, uses bundled artifacts from the crate
    #[arg(long = "artifacts-path", default_value = "./artifacts/")]
    pub artifacts_path: Option<PathBuf>,

    /// Optional: Field type for proving backend (e.g., "kb" for KoalaBear, "bb" for BabyBear)
    /// Default: "kb"
    #[arg(long = "field-type", default_value = "kb")]
    pub field_type: String,

    /// Optional path to write proof artifact as JSON
    #[arg(long, value_name = "PATH")]
    pub output_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PicoGenerateEvmInputsArgs {
    /// Path to directory containing EVM proof artifacts
    #[arg(long = "artifacts-path")]
    pub artifacts_path: PathBuf,
}

/// Handle Pico CLI commands
pub async fn run<P: Provider>(command: PicoCommand, quote_bytes: Option<Vec<u8>>, provider: &P, version: automata_dcap_utils::Version, tcb_eval_num: Option<u32>) -> Result<()> {
    match command {
        PicoCommand::Prove(args) => {
            let quote_bytes = quote_bytes.context("Quote bytes must be provided for proving")?;
            prove(&args, quote_bytes, provider, version, tcb_eval_num).await
        },
        PicoCommand::GenerateEvmInputs(args) => generate_evm_inputs(&args),
        PicoCommand::ProgramId => program_id(version),
    }
}

/// Generate proof for DCAP quote verification
async fn prove<P: Provider>(args: &PicoProveArgs, quote_bytes: Vec<u8>, provider: &P, version: automata_dcap_utils::Version, tcb_eval_num: Option<u32>) -> Result<()> {
    // Prepare version-aware guest input using common workflow
    let input_bytes = prepare_guest_input(provider, Some(version), &quote_bytes, tcb_eval_num).await?;

    // Create version-aware prover
    let prover = PicoProver::new(version)?;

    // Build Pico configuration
    let config = if let Some(ref path) = args.artifacts_path {
        PicoConfig::new(path.clone()).with_field_type(args.field_type.clone())
    } else {
        PicoConfig::default().with_field_type(args.field_type.clone())
    };

    // Generate proof using Pico prover
    let (journal, proof) = prover.prove(&config, &input_bytes).await?;

    // Display results
    display_proof_result(&journal, &proof, "Groth16 Proof", version)?;

    // Write proof artifact if output path is provided
    if let Some(ref output_path) = args.output_path {
        let program_id = prover.program_identifier()?;
        let circuit_version = PicoProver::circuit_version();
        let artifact = ProofArtifact {
            zkvm: "pico".to_string(),
            program_id,
            circuit_version,
            journal: hex::encode(&journal),
            proof: hex::encode(&proof),
        };
        write_proof_artifact(output_path, &artifact)?;
    }

    Ok(())
}

/// Generate EVM contract inputs from proof artifacts
fn generate_evm_inputs(args: &PicoGenerateEvmInputsArgs) -> Result<()> {
    use num::Num;
    use num_bigint::BigInt;
    use serde_json::json;
    use std::fs::{self, File};
    use std::io::{BufReader, Write};

    const GROTH16_JSON_FILE: &str = "groth16_witness.json";
    const PV_FILE: &str = "pv_file";
    const PROOF_FILE: &str = "proof.data";
    const CONTRACT_INPUTS_FILE: &str = "inputs.json";

    let artifacts_path = &args.artifacts_path;

    // Check proof file exists
    let proof_path = artifacts_path.join(PROOF_FILE);
    if !proof_path.exists() {
        anyhow::bail!("Proof file does not exist at {}", proof_path.display());
    }

    // Check witness file exists
    let witness_path = artifacts_path.join(GROTH16_JSON_FILE);
    if !witness_path.exists() {
        anyhow::bail!("Witness file does not exist at {}", witness_path.display());
    }

    // Get vkey_hash from witness file
    let witness_file = File::open(&witness_path)?;
    let witness_reader = BufReader::new(witness_file);
    let witness_json: serde_json::Value = serde_json::from_reader(witness_reader)?;
    let vkey_hash_str = witness_json["vkey_hash"]
        .as_str()
        .context("vkey_hash not found in witness file")?;
    let vkey_hash_bigint = BigInt::from_str_radix(vkey_hash_str, 10)?;
    let vkey_hex_string = format!("{:x}", vkey_hash_bigint);
    let vkey_hex = format!("0x{:0>64}", vkey_hex_string);

    // Get proof from proof.data
    let proof_data = fs::read_to_string(&proof_path)?;
    let proof_slice: Vec<String> = proof_data.split(',').map(|s| s.to_string()).collect();
    let proof = &proof_slice[0..8];

    // Get pv stream from pv file
    let pv_file_path = artifacts_path.join(PV_FILE);
    if !pv_file_path.exists() {
        anyhow::bail!("PV file does not exist at {}", pv_file_path.display());
    }
    let pv_file_content = fs::read_to_string(&pv_file_path)?;
    let pv_string = pv_file_content.trim();
    if !pv_string[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid hex format in pv file");
    }

    let public_values_hex = "0x".to_string() + pv_string;
    let result_json = json!({
        "riscvVKey": vkey_hex,
        "proof": proof,
        "publicValues": public_values_hex
    });

    let json_string = serde_json::to_string_pretty(&result_json)?;

    log::info!("Contract input JSON: {}", json_string);

    // Write to inputs.json
    let contract_input_path = artifacts_path.join(CONTRACT_INPUTS_FILE);
    let mut contract_input_file = File::create(&contract_input_path)?;
    contract_input_file.write_all(json_string.as_bytes())?;

    println!("Generated EVM contract inputs at: {}", contract_input_path.display());

    Ok(())
}

/// Display the program identifier (vkey hash) for on-chain verification
fn program_id(version: automata_dcap_utils::Version) -> Result<()> {
    let prover = PicoProver::new(version)?;
    let program_id = prover.program_identifier()?;
    println!("Pico DCAP Program Identifier: {}", program_id);
    Ok(())
}
