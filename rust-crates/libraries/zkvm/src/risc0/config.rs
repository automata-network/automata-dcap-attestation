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
