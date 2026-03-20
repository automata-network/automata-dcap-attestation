use std::path::PathBuf;

use clap::ValueEnum;

/// Default BrevisMarket contract address on Base (chain ID 8453)
pub const DEFAULT_BREVIS_MARKET: &str = "0xcCec2a9FE35b6B5F23bBF303A4e14e5895DeA127";
/// Default BREV token contract address on Base
pub const DEFAULT_BREV_TOKEN: &str = "0x086F405146Ce90135750Bbec9A063a8B20A8bfFb";
/// Default StakingController contract address on Base (used to query minSelfStake)
pub const DEFAULT_STAKING_CONTROLLER: &str = "0x9c0D8C5F10f0d3A02D04556a4499964a75DBf4A3";
/// Base chain ID
pub const DEFAULT_BASE_CHAIN_ID: u64 = 8453;

/// Proving strategy for Pico zkVM
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProvingStrategy {
    #[default]
    #[value(name = "local")]
    Local,
    #[value(name = "marketplace")]
    Marketplace,
}

/// Configuration for Pico zkVM proving
#[derive(Debug, Clone)]
pub struct PicoConfig {
    /// Proving strategy (local or marketplace)
    pub proving_strategy: ProvingStrategy,

    /// Path to the directory containing EVM proof artifacts (vm_pk, vm_vk, constraints.json)
    pub artifacts_path: PathBuf,

    /// Field type for proving backend (e.g., "kb" for KoalaBear, "bb" for BabyBear)
    /// Default: "kb" (KoalaBear)
    pub field_type: String,

    /// Optional marketplace configuration (required when proving_strategy is Marketplace)
    pub marketplace: Option<MarketplaceConfig>,
}

impl Default for PicoConfig {
    fn default() -> Self {
        Self {
            proving_strategy: ProvingStrategy::default(),
            // Default to bundled artifacts in the crate
            artifacts_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/pico/artifacts"),
            field_type: "kb".to_string(),
            marketplace: None,
        }
    }
}

impl PicoConfig {
    /// Create a new PicoConfig with custom artifacts path
    pub fn new(artifacts_path: PathBuf) -> Self {
        Self {
            artifacts_path,
            ..Default::default()
        }
    }

    /// Set the field type for the proving backend
    pub fn with_field_type(mut self, field_type: String) -> Self {
        self.field_type = field_type;
        self
    }

    /// Set the proving strategy
    pub fn with_proving_strategy(mut self, strategy: ProvingStrategy) -> Self {
        self.proving_strategy = strategy;
        self
    }

    /// Set marketplace configuration
    pub fn with_marketplace(mut self, marketplace: MarketplaceConfig) -> Self {
        self.marketplace = Some(marketplace);
        self
    }
}

/// Configuration for Brevis Prover Network marketplace on Base
#[derive(Debug, Clone)]
pub struct MarketplaceConfig {
    /// Base chain RPC URL (chain ID 8453)
    pub rpc_url: Option<String>,
    /// Wallet private key for signing transactions (hex-encoded)
    pub private_key: Option<String>,
    /// URL where the ELF binary is hosted (e.g., IPFS)
    pub elf_url: String,
    /// URL where input data is hosted (optional, for large inputs)
    pub input_url: Option<String>,
    /// BrevisMarket contract address (defaults to mainnet)
    pub brevis_market_address: Option<String>,
    /// BREV token contract address (defaults to mainnet)
    pub brev_token_address: Option<String>,
    /// StakingController contract address (defaults to Base mainnet, used to query minSelfStake)
    pub staking_controller_address: Option<String>,
    /// Maximum fee in BREV tokens (wei). If None, auto-estimated from on-chain marketplace stats.
    pub max_fee: Option<u128>,
    /// Multiplier applied to the estimated average fee when auto-estimating max_fee.
    /// Only used when max_fee is None. Default: 3.0
    pub fee_multiplier: Option<f64>,
    /// Minimum prover stake required (wei). If None, queried from StakingController.minSelfStake()
    pub min_stake: Option<u128>,
    /// Deadline as unix timestamp (computed from duration at submission time)
    pub deadline: u64,
    /// Unique nonce per request (auto-generated if not provided)
    pub nonce: u64,
    /// Pico verifier version (default 0)
    pub version: Option<u32>,
    /// Poll interval in seconds for checking proof status (default 30)
    pub poll_interval: Option<u64>,
}
