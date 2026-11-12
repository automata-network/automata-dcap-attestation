use clap::ValueEnum;

/// Proving strategy for RISC Zero
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProvingStrategy {
    #[value(name = "bonsai")]
    Bonsai,
    #[value(name = "boundless")]
    Boundless,
}

impl Default for ProvingStrategy {
    fn default() -> Self {
        ProvingStrategy::Bonsai
    }
}

/// Configuration for RISC Zero prover
#[derive(Debug, Clone)]
pub struct Risc0Config {
    pub proving_strategy: ProvingStrategy,
    pub bonsai: Option<BonsaiConfig>,
    pub boundless: Option<BoundlessConfig>,
}

impl Default for Risc0Config {
    fn default() -> Self {
        Self {
            proving_strategy: ProvingStrategy::default(),
            bonsai: None,
            boundless: None,
        }
    }
}

impl Risc0Config {
    pub(crate) fn validate_v2(&self) -> anyhow::Result<()> {
        if self.proving_strategy == ProvingStrategy::Bonsai {
            if let Some(config) = &self.bonsai {
                // Upstream Bonsai reads process environment, not this per-request config.
                for (requested, name) in [
                    (&config.api_url, "BONSAI_API_URL"),
                    (&config.api_key, "BONSAI_API_KEY"),
                ] {
                    if let Some(requested) = requested {
                        anyhow::ensure!(
                            std::env::var(name).ok().as_ref() == Some(requested),
                            "V2 Bonsai configuration must match {name}; set the environment before starting the process"
                        );
                    }
                }
            }
        }
        if self.proving_strategy == ProvingStrategy::Boundless {
            let config = self
                .boundless
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Boundless config is required"))?;
            anyhow::ensure!(
                config.proof_type == BoundlessProofType::Groth16,
                "V2 requires RISC Zero 3.1 Groth16; set aggregation is unsafe and unsupported"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_rejects_aggregation_before_proving() {
        let mut config = Risc0Config::default();
        assert!(config.validate_v2().is_ok());
        config.proving_strategy = ProvingStrategy::Boundless;
        assert!(config.validate_v2().is_err());
        config.boundless = Some(BoundlessConfig::default());
        assert!(config.validate_v2().is_ok());
        config.boundless.as_mut().unwrap().proof_type = BoundlessProofType::Merkle;
        assert!(config.validate_v2().is_err());
    }

    #[test]
    fn v2_cannot_silently_ignore_bonsai_configuration() {
        let mut config = Risc0Config {
            bonsai: Some(BonsaiConfig::default()),
            ..Default::default()
        };
        assert!(config.validate_v2().is_ok());
        config.bonsai.as_mut().unwrap().api_url = Some(format!(
            "{}-different",
            std::env::var("BONSAI_API_URL").unwrap_or_default()
        ));
        assert!(config
            .validate_v2()
            .unwrap_err()
            .to_string()
            .contains("BONSAI_API_URL"));
        config.bonsai = Some(BonsaiConfig::default());
        config.bonsai.as_mut().unwrap().api_key = Some(format!(
            "{}-different",
            std::env::var("BONSAI_API_KEY").unwrap_or_default()
        ));
        let error = config.validate_v2().unwrap_err().to_string();
        assert!(error.contains("BONSAI_API_KEY"));
        assert!(!error.contains("-different"));
    }
}

/// Configuration for Bonsai proving
#[derive(Debug, Clone)]
pub struct BonsaiConfig {
    pub api_url: Option<String>,
    pub api_key: Option<String>,
}

impl Default for BonsaiConfig {
    fn default() -> Self {
        Self {
            api_url: std::env::var("BONSAI_API_URL").ok(),
            api_key: std::env::var("BONSAI_API_KEY").ok(),
        }
    }
}

/// Proof type for Boundless proving
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BoundlessProofType {
    #[value(name = "groth16")]
    Groth16,
    #[value(name = "merkle")]
    Merkle,
}

impl Default for BoundlessProofType {
    fn default() -> Self {
        BoundlessProofType::Groth16
    }
}

/// Configuration for Boundless proving
#[derive(Debug, Clone)]
pub struct BoundlessConfig {
    pub rpc_url: Option<String>,
    pub private_key: Option<String>,
    pub program_url: Option<String>,
    pub proof_type: BoundlessProofType,
    pub min_price: Option<u128>,
    pub max_price: Option<u128>,
    pub timeout: Option<u32>,
    pub ramp_up_period: Option<u32>,
}

impl Default for BoundlessConfig {
    fn default() -> Self {
        Self {
            rpc_url: std::env::var("BOUNDLESS_RPC_URL").ok(),
            private_key: std::env::var("BOUNDLESS_PRIVATE_KEY").ok(),
            program_url: None,
            proof_type: BoundlessProofType::default(),
            min_price: None,
            max_price: None,
            timeout: None,
            ramp_up_period: None,
        }
    }
}
