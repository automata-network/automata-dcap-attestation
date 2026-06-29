use anyhow::{Context, Result};
use pico_sdk::client::DefaultProverClient;

use super::super::config::PicoConfig;

/// Prove locally using the Pico zkVM prover.
///
/// This performs the expensive SNARK proving step locally. The caller is responsible
/// for emulation (to obtain the journal) before calling this function.
///
/// Returns the 256-byte Groth16 proof (8 × 32-byte field elements).
pub async fn prove_local(
    elf: &'static [u8],
    input_bytes: &[u8],
    config: &PicoConfig,
) -> Result<Vec<u8>> {
    let config = config.clone();
    let input_bytes = input_bytes.to_vec();

    // Run the blocking proving operation in a separate thread
    tokio::task::spawn_blocking(move || {
        let client = DefaultProverClient::new(elf);
        let mut stdin_builder = client.new_stdin_builder();
        stdin_builder.write_slice(&input_bytes);

        println!("Begin proving with Pico zkVM (field: {})", config.field_type);

        // Check if trusted setup is needed (vm_pk exists)
        let proving_key_path = config.artifacts_path.join("vm_pk");
        let need_setup = !proving_key_path.exists();

        if need_setup {
            println!("Performing trusted setup (first time)...");
        } else {
            log::info!("Using existing proving key at {:?}", proving_key_path);
        }

        client
            .prove_evm(
                stdin_builder,
                need_setup,
                config.artifacts_path.clone(),
                &config.field_type,
            )
            .context("Failed to generate Pico proof")?;

        log::info!("Proof generated successfully");

        // Read and encode proof from proof.data
        let proof_data_path = config.artifacts_path.join("proof.data");
        let proof_bytes = if proof_data_path.exists() {
            let proof_data = std::fs::read_to_string(&proof_data_path)
                .context("Failed to read proof.data")?;

            // Parse comma-separated hex strings
            let hex_strings: Vec<&str> = proof_data.split(',').collect();

            if hex_strings.len() < 8 {
                anyhow::bail!(
                    "Invalid proof.data: expected at least 8 values, got {}",
                    hex_strings.len()
                );
            }

            // Take first 8 values (the proof), last 2 are witness
            let proof_values = &hex_strings[0..8];

            // Encode as uint256[8]: concatenate 8 × 32 bytes
            let mut encoded = Vec::with_capacity(8 * 32);
            for hex_str in proof_values {
                let hex_str = hex_str.trim().trim_start_matches("0x");
                let bytes = hex::decode(hex_str)
                    .context("Failed to decode proof hex string")?;

                if bytes.len() != 32 {
                    anyhow::bail!(
                        "Invalid proof value: expected 32 bytes, got {}",
                        bytes.len()
                    );
                }

                encoded.extend_from_slice(&bytes);
            }

            encoded
        } else {
            log::warn!("proof.data not found, returning empty proof");
            Vec::new()
        };

        Ok(proof_bytes)
    })
    .await
    .context("Local proving task panicked")?
}
