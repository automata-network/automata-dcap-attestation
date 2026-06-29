use anyhow::{Context, Result};
use async_trait::async_trait;
use ff::PrimeField as _;
use pico_sdk::client::{DefaultProverClient, KoalaBearProverClient};
use pico_sdk::HashableKey;

use super::config::{PicoConfig, ProvingStrategy};
use super::proving::{prove_local, prove_with_marketplace};
use crate::{
    common::{ZkVm, ZkVmProver},
    get_elf, Version,
};

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
        // Always emulate locally first to get journal (this is fast)
        let client = DefaultProverClient::new(self.elf);

        let mut stdin_builder = client.new_stdin_builder();
        stdin_builder.write_slice(input_bytes);

        println!("Emulating program...");
        let (reports, public_buffer) = client.emulate(stdin_builder.clone());
        let cycles = reports.last().map(|r| r.current_cycle).unwrap_or(0);
        log::info!("EVM Emulation Cycles: {:?}", cycles);

        // Parse the journal from the public buffer
        let journal = parse_public_buffer(&public_buffer)?;

        // Check if DEV_MODE is set — if so, skip proving entirely
        if std::env::var("DEV_MODE").is_ok() && !std::env::var("DEV_MODE").unwrap().is_empty() {
            println!("DEV_MODE enabled, skipping proof generation");
            return Ok((journal, vec![]));
        }

        println!("Begin proving with strategy: {:?}", config.proving_strategy);

        // Dispatch to the appropriate proving strategy
        let proof_bytes = match config.proving_strategy {
            ProvingStrategy::Local => prove_local(self.elf, input_bytes, config).await?,
            ProvingStrategy::Marketplace => {
                let marketplace_config = config.marketplace.as_ref().context(
                    "Marketplace config must be provided when using marketplace strategy",
                )?;

                // Compute VK and public values digest for the marketplace request
                let vk = self.compute_vk()?;
                let pv_digest = compute_public_values_digest(&public_buffer);

                // The Brevis proving service expects inputs as a bincode-serialized
                // EmulatorStdinBuilder, not raw application bytes. It deserializes
                // this builder on its end before passing data to the guest program.
                // Example: https://github.com/brevis-network/pico-proving-service/blob/396f24d165b47d0759b157db7288c20e6318b171/bin/gen_input_example.rs#L68-L81
                let serialized_stdin = bincode::serialize(&stdin_builder)
                    .context("Failed to serialize EmulatorStdinBuilder for marketplace proving")?;

                prove_with_marketplace(
                    self.elf,
                    &serialized_stdin,
                    vk,
                    pv_digest,
                    marketplace_config,
                )
                .await?
            }
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
        let repr = vk_digest_bn254.value.to_repr();
        let vk_bytes = num_bigint::BigUint::from_bytes_le(repr.as_ref()).to_bytes_be();

        // Pad to 32 bytes
        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vk_bytes);

        // Return as hex string
        Ok(format!("0x{}", hex::encode(result)))
    }

    /// The current circuit version
    /// As specified in <https://github.com/brevis-network/pico/blob/main/Cargo.toml>
    fn circuit_version() -> String {
        "v1.2.2".to_string()
    }
}

impl PicoProver {
    /// Compute the 32-byte verification key hash for this ELF program.
    ///
    /// This is the BN254-friendly VK digest that the BrevisMarket contract uses
    /// to identify which program is being proven.
    fn compute_vk(&self) -> Result<[u8; 32]> {
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk();
        let vk_digest_bn254 = vk.hash_bn254();

        let repr = vk_digest_bn254.value.to_repr();
        let vk_bytes = num_bigint::BigUint::from_bytes_le(repr.as_ref()).to_bytes_be();

        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vk_bytes);
        Ok(result)
    }
}

/// Compute a SHA-256 digest of the public values buffer, masked to 253 bits
/// for BN254 scalar field compatibility.
///
/// This matches the Brevis proving service's computation:
/// <https://github.com/brevis-network/pico-proving-service/blob/396f24d/src/cost_estimation.rs#L73-L75>
///
/// The BrevisMarket contract uses this digest to tie a proof request
/// to specific expected outputs, preventing provers from submitting
/// proofs for different inputs.
fn compute_public_values_digest(public_buffer: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut result: [u8; 32] = Sha256::digest(public_buffer).into();
    // Clear top 3 bits (bits 255, 254, 253) to fit in BN254 scalar field
    result[0] &= 0x1F;
    result
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
