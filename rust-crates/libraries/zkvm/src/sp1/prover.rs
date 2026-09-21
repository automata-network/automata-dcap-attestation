use anyhow::{Context, Result};
use async_trait::async_trait;
use sp1_sdk::{
    network::NetworkMode, Elf, HashableKey, LightProver, Prover, ProverClient, ProvingKey,
    SP1Stdin, SP1_CIRCUIT_VERSION,
};

use super::{config::Sp1Config, proving::prove};
use crate::{common::ZkVmProver, Version};

/// SP1 zkVM prover implementation
pub struct Sp1Prover {
    /// The ELF binary for the guest program
    elf: std::borrow::Cow<'static, [u8]>,
}

impl Sp1Prover {
    /// Load an explicitly selected V2 release ELF. Its native program_identifier must match
    /// the audited release manifest and the on-chain V2 allowlist before submission.
    pub fn from_v2_elf(elf: Vec<u8>) -> Result<Self> {
        validate_v6_elf(&elf)?;
        Ok(Self {
            elf: std::borrow::Cow::Owned(elf),
        })
    }
}

#[async_trait]
impl ZkVmProver for Sp1Prover {
    type Config = Sp1Config;

    fn new(version: Version) -> Result<Self> {
        if version == Version::V2_0 {
            return Self::from_v2_elf(crate::load_v2_elf()?);
        }
        anyhow::bail!("SP1 6.8.0 cannot run bundled v5/ELF32 guests; select V2 with a reviewed ELF64 artifact")
    }

    async fn prove(&self, config: &Self::Config, input_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Setup stdin
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input_bytes);

        // Check if DEV_MODE is set - if so, skip proving
        if std::env::var("DEV_MODE").is_ok() {
            log::info!("DEV_MODE detected - skipping proof generation");

            // Use local prover to execute and get journal
            let client = LightProver::new().await;
            let (journal, report) = client.execute(Elf::from(self.elf.as_ref()), stdin).await?;
            anyhow::ensure!(report.exit_code == 0, "SP1 guest failed");
            log::info!(
                "executed program with {} cycles",
                report.total_instruction_count()
            );
            return Ok((journal.to_vec(), vec![]));
        }

        println!("Begin proving with proof system: {:?}", config.proof_system);

        // Explicit client configuration avoids mutating process-wide credentials/prover mode.
        let mut builder = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .private_key(&config.private_key);
        if let Some(url) = &config.rpc_url {
            builder = builder.rpc_url(url);
        }
        let client = builder.build().await;

        // Setup: get proving key and verifying key
        let pk = client.setup(Elf::from(self.elf.as_ref())).await?;

        let vk_string = pk.verifying_key().bytes32();
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

        // Keep the shared synchronous trait callable inside the async CLI. The v6
        // setup runs on its own runtime thread, never a nested block_on/mock prover.
        let elf = Elf::from(self.elf.as_ref());
        std::thread::spawn(move || -> Result<String> {
            tokio::runtime::Runtime::new()?.block_on(async move {
                let client = LightProver::new().await;
                let pk = client.setup(elf).await?;
                Ok(pk.verifying_key().bytes32())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("SP1 setup thread panicked"))?
    }

    fn circuit_version() -> String {
        SP1_CIRCUIT_VERSION.to_string()
    }
}

/// Reject old ELF32 artifacts before any setup or remote prover request.
pub fn validate_v6_elf(elf: &[u8]) -> Result<()> {
    anyhow::ensure!(
        elf.len() >= 20 && &elf[..6] == b"\x7fELF\x02\x01" && elf[18..20] == [0xf3, 0],
        "SP1 6.8.0 requires little-endian ELF64 RISC-V; rebuild the guest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_v6_elf;
    #[test]
    fn rejects_legacy_and_wrong_architecture_elf() {
        let mut header = vec![0; 20];
        header[..6].copy_from_slice(b"\x7fELF\x02\x01");
        header[18] = 0xf3;
        assert!(validate_v6_elf(&header).is_ok());
        header[4] = 1;
        assert!(validate_v6_elf(&header).is_err());
        header[4] = 2;
        header[18] = 0x3e;
        assert!(validate_v6_elf(&header).is_err());
        assert!(validate_v6_elf(b"\x7fELF").is_err());
    }
}
