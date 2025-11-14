use anyhow::{Context, Result};
use async_trait::async_trait;
use sp1_sdk::{
    network::NetworkMode, HashableKey, Prover, ProverClient, SP1Stdin, SP1_CIRCUIT_VERSION,
};

use crate::{common::{ZkVmProver, ZkVm}, get_elf, Version};
use super::{config::Sp1Config, proving::prove};

/// SP1 zkVM prover implementation
pub struct Sp1Prover {
    /// The ELF binary for the guest program
    elf: &'static [u8],
}

#[async_trait]
impl ZkVmProver for Sp1Prover {
    type Config = Sp1Config;

    fn new(version: Version) -> Result<Self> {
        let elf = get_elf(version, ZkVm::Sp1)?;
        Ok(Self { elf })
    }

    async fn prove(&self, config: &Self::Config, input_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Setup stdin
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input_bytes);

        // Check if DEV_MODE is set - if so, skip proving
        if std::env::var("DEV_MODE").is_ok() {
            log::info!("DEV_MODE detected - skipping proof generation");

            // Use local prover to execute and get journal
            std::env::set_var("SP1_PROVER", "mock");
            let client = ProverClient::from_env();
            let (journal, report) = client.execute(self.elf, &stdin).run()?;
            log::info!(
                "executed program with {} cycles",
                report.total_instruction_count()
            );
            return Ok((journal.to_vec(), vec![]));
        }

        println!("Begin proving with proof system: {:?}", config.proof_system);

        // Set up SP1 environment variables
        std::env::set_var("SP1_PROVER", "network");

        // Get private key from config or environment
        let sp1_network_key = config.private_key.as_str();
        std::env::set_var("NETWORK_PRIVATE_KEY", sp1_network_key);

        // Create network prover client
        let client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .build();

        // Setup: get proving key and verifying key
        let (pk, vk) = client.setup(self.elf);

        let vk_string = vk.bytes32();
        log::info!("VK: {}", vk_string.as_str());

        // Generate proof
        let (journal, proof_bytes) = prove(
            &client,
            &pk,
            &stdin,
            config.proof_system,
            config.network_mode,
        )
        .await
        .context("SP1 proving failed")?;

        Ok((journal, proof_bytes))
    }

    fn program_identifier(&self) -> Result<String> {
        log::info!("Computing verifying key for SP1 DCAP program...");

        // Use MOCK prover to compute VK
        std::env::set_var("SP1_PROVER", "mock");

        let client = ProverClient::from_env();
        let (_, vk) = client.setup(self.elf);

        Ok(vk.bytes32())
    }

    fn circuit_version() -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }
}
