use anyhow::{Context, Result};
use async_trait::async_trait;
use risc0_zkvm::{compute_image_id, default_executor, ExecutorEnv, VERSION};

use crate::{common::{ZkVmProver, ZkVm}, get_elf, Version};
use super::{
    config::{ProvingStrategy, Risc0Config},
    proving::{prove_with_bonsai, prove_with_boundless},
};

/// RISC0 zkVM prover implementation
pub struct Risc0Prover {
    /// The ELF binary for the guest program
    elf: &'static [u8],
}

#[async_trait]
impl ZkVmProver for Risc0Prover {
    type Config = Risc0Config;

    fn new(version: Version) -> Result<Self> {
        let elf = get_elf(version, ZkVm::Risc0)?;
        Ok(Self { elf })
    }

    async fn prove(&self, config: &Self::Config, input_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Log image ID and version info
        let image_id = compute_image_id(self.elf)?;
        log::info!("Image ID: {}", image_id.to_string());
        log::info!("RiscZero Version: {}", &Self::circuit_version());
        log::debug!("Guest input: {}", hex::encode(input_bytes));

        // Set RISC0 info logging
        std::env::set_var("RISC0_INFO", "1");

        // Execute locally to get journal
        log::info!("Executing locally to get journal...");
        let env = ExecutorEnv::builder().write_slice(&input_bytes).build()?;
        let session_info = default_executor().execute(env, self.elf)?;
        log::debug!("Session Info: {:?}", &session_info);
        let journal = session_info.journal.bytes.to_vec();

        // Check if DEV_MODE is set - if so, skip proving
        if std::env::var("DEV_MODE").is_ok() {
            log::info!("DEV_MODE detected - skipping proof generation");
            return Ok((journal, vec![]));
        }

        println!("Begin proving with strategy: {:?}", config.proving_strategy);

        // Generate proof based on strategy
        let seal = match config.proving_strategy {
            ProvingStrategy::Bonsai => prove_with_bonsai(self.elf, input_bytes)
                .await
                .context("Bonsai proving failed")?,
            ProvingStrategy::Boundless => {
                let boundless_config = config.boundless.as_ref()
                    .context("Boundless config must be provided when using Boundless strategy")?;
                prove_with_boundless(self.elf, input_bytes, boundless_config)
                    .await
                    .context("Boundless proving failed")?
            }
        };

        Ok((journal, seal))
    }

    fn program_identifier(&self) -> Result<String> {
        let image_id = compute_image_id(self.elf)?;
        Ok(image_id.to_string())
    }

    fn circuit_version() -> String {
        VERSION.to_string()
    }
}
