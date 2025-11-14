use clap::ValueEnum;

/// Proof system supported by SP1
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProofSystem {
    #[value(name = "groth16")]
    Groth16,
    #[value(name = "plonk")]
    Plonk,
}

impl Default for ProofSystem {
    fn default() -> Self {
        ProofSystem::Groth16
    }
}

/// Network prover mode for SP1
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkProverMode {
    /// Uses Succinct Labs on-demand prover
    #[value(name = "hosted")]
    Hosted,
    /// Uses an already existing agreement with a fulfiller
    #[value(name = "reserved")]
    Reserved,
    /// Uses prover network on mainnet (default)
    #[value(name = "auction")]
    Auction,
}

impl Default for NetworkProverMode {
    fn default() -> Self {
        NetworkProverMode::Auction
    }
}

/// Configuration for SP1 prover
#[derive(Debug, Clone)]
pub struct Sp1Config {
    pub proof_system: ProofSystem,
    pub network_mode: NetworkProverMode,
    pub private_key: String,
    pub rpc_url: Option<String>,
}

impl Default for Sp1Config {
    fn default() -> Self {
        Self {
            proof_system: ProofSystem::default(),
            network_mode: NetworkProverMode::default(),
            private_key: std::env::var("SP1_NETWORK_PRIVATE_KEY").unwrap(),
            rpc_url: std::env::var("SP1_RPC_URL").ok(),
        }
    }
}
