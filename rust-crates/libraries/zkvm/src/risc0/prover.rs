use anyhow::{Context, Result};
use async_trait::async_trait;
use risc0_zkvm::{compute_image_id, default_executor, ExecutorEnv, VERSION};

use super::{
    config::{ProvingStrategy, Risc0Config},
    proving::{prove_with_bonsai, prove_with_boundless},
};
use crate::{
    common::{ZkVm, ZkVmProver},
    get_elf, Version,
};

/// RISC0 zkVM prover implementation
pub struct Risc0Prover {
    /// The ELF binary for the guest program
    elf: std::borrow::Cow<'static, [u8]>,
}

impl Risc0Prover {
    /// Load an explicitly selected V2 release ELF. Its native program_identifier must match
    /// the audited release manifest and the on-chain V2 allowlist before submission.
    pub fn from_v2_elf(elf: Vec<u8>) -> Result<Self> {
        // RISC Zero 3.x canonical artifacts may be combined user/kernel programs,
        // not raw ELFs. Validate with the same decoder used to derive the image ID.
        compute_image_id(&elf).context("invalid V2 RISC Zero program")?;
        Ok(Self {
            elf: std::borrow::Cow::Owned(elf),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_rejects_malformed_programs_not_just_bad_magic() {
        for bytes in [
            b"".as_slice(),
            b"\x7fELF".as_slice(),
            b"invalid program".as_slice(),
        ] {
            assert!(Risc0Prover::from_v2_elf(bytes.to_vec()).is_err());
        }
    }
}

#[async_trait]
impl ZkVmProver for Risc0Prover {
    type Config = Risc0Config;

    fn new(version: Version) -> Result<Self> {
        if version == Version::V2_0 {
            return Self::from_v2_elf(crate::load_v2_elf()?);
        }
        let elf = get_elf(version, ZkVm::Risc0)?;
        Ok(Self {
            elf: std::borrow::Cow::Borrowed(elf),
        })
    }

    async fn prove(&self, config: &Self::Config, input_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Log image ID and version info
        let image_id = compute_image_id(self.elf.as_ref())?;
        log::info!("Image ID: {}", image_id.to_string());
        log::info!("RiscZero Version: {}", &Self::circuit_version());
        log::debug!("Guest input: {}", hex::encode(input_bytes));

        // Set RISC0 info logging
        std::env::set_var("RISC0_INFO", "1");

        // Execute locally to get journal
        log::info!("Executing locally to get journal...");
        let env = ExecutorEnv::builder().write_slice(&input_bytes).build()?;
        let session_info = default_executor().execute(env, self.elf.as_ref())?;
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
            ProvingStrategy::Bonsai => prove_with_bonsai(self.elf.as_ref(), input_bytes)
                .await
                .context("Bonsai proving failed")?,
            ProvingStrategy::Boundless => {
                let boundless_config = config
                    .boundless
                    .as_ref()
                    .context("Boundless config must be provided when using Boundless strategy")?;
                prove_with_boundless(self.elf.as_ref(), input_bytes, boundless_config)
                    .await
                    .context("Boundless proving failed")?
            }
        };

        Ok((journal, seal))
    }

    fn program_identifier(&self) -> Result<String> {
        let image_id = compute_image_id(self.elf.as_ref())?;
        Ok(image_id.to_string())
    }

    fn circuit_version() -> String {
        VERSION.to_string()
    }
}
