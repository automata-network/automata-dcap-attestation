use anyhow::{Context, Result};
use async_trait::async_trait;
use p3_field::PrimeField;
use pico_sdk::client::{DefaultProverClient, KoalaBearProverClient};
use pico_sdk::HashableKey;

use crate::{common::{ZkVmProver, ZkVm}, get_elf, Version};
use super::config::PicoConfig;

/// Pico zkVM prover implementation
pub struct PicoProver {
    /// The ELF binary for the guest program
    elf: &'static [u8],
}

#[async_trait]
impl ZkVmProver for PicoProver {
    type Config = PicoConfig;

    fn new(version: Version) -> Result<Self> {
        let elf = get_elf(version, ZkVm::Pico)?;
        Ok(Self { elf })
    }

    async fn prove(&self, config: &Self::Config, input_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Initialize the prover client
        let client = DefaultProverClient::new(self.elf);

        // Initialize new stdin builder
        let mut stdin_builder = client.new_stdin_builder();
        stdin_builder.write_slice(input_bytes);

        // Emulate first to get public buffer
        println!("Emulating program...");
        let (cycles, public_buffer) = client.emulate(stdin_builder.clone());
        log::info!("EVM Emulation Cycles: {}", cycles);

        // Generate proof if not in dev mode
        if std::env::var("DEV_MODE").is_err() || std::env::var("DEV_MODE").unwrap().is_empty() {
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
        } else {
            println!("DEV_MODE enabled, skipping proof generation");
        }

        // Parse the journal (public buffer)
        let journal = parse_public_buffer(&public_buffer)?;

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

            // Encode as uint256[8]: just concatenate 8 * 32 bytes
            let mut encoded = Vec::with_capacity(8 * 32);

            // Concatenate the 8 proof values (each already 32 bytes)
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

        Ok((journal, proof_bytes))
    }

    fn program_identifier(&self) -> Result<String> {
        println!("Computing program identifier for Pico DCAP program...");

        // Create KoalaBear client to compute VK
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk();
        let vk_digest_bn254 = vk.hash_bn254();

        // Convert to bytes
        let vk_bytes = vk_digest_bn254.as_canonical_biguint().to_bytes_be();

        // Pad to 32 bytes
        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vk_bytes);

        // Return as hex string
        Ok(format!("0x{}", hex::encode(result)))
    }

    /// The current circuit version
    /// As specified in <https://github.com/brevis-network/pico/blob/main/Cargo.toml>
    fn circuit_version() -> String {
        "v1.1.6".to_string()
    }
}

/// Parse the public buffer to extract the journal
///
/// The public buffer format is:
/// - 2 bytes: output length (big-endian u16)
/// - N bytes: VerifiedOutput
/// - 8 bytes: current timestamp (big-endian u64)
/// - 32 bytes: tcbinfo root hash
/// - 32 bytes: enclave identity root hash
/// - 32 bytes: root cert hash
/// - 32 bytes: signing cert hash
/// - 32 bytes: root CRL hash
/// - 32 bytes: PCK CRL hash
fn parse_public_buffer(public_buffer: &[u8]) -> Result<Vec<u8>> {
    // Read output length (2 bytes, big-endian)
    if public_buffer.len() < 2 {
        anyhow::bail!("Public buffer too short");
    }
    let output_len = u16::from_be_bytes(
        public_buffer[0..2]
            .try_into()
            .context("Failed to read output length")?,
    );

    // Verify we have enough data
    let total_expected = 2 + output_len as usize + 8 + (32 * 6);
    if public_buffer.len() < total_expected {
        anyhow::bail!(
            "Public buffer too short: expected at least {} bytes, got {}",
            total_expected,
            public_buffer.len()
        );
    }

    // Return the entire public buffer as journal
    Ok(public_buffer.to_vec())
}
