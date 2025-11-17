use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use automata_dcap_utils::Version;
use std::collections::HashMap;

/// Identifies a deployed on-chain contract that DCAP tooling interacts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractKind {
    // PCCS DAO contracts
    EnclaveIdDao,
    FmspcTcbDao,
    PckDao,
    PcsDao,
    TcbEvalDao,
    // DCAP contracts
    DcapAttestation,
    PccsRouter,
}

/// Versioned DAO that supports multiple TCB evaluation data numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedDao {
    /// Maps tcbEvaluationDataNumber to contract address
    /// New networks have keys: 17, 18, 19, 20
    pub versioned: HashMap<u32, Address>,
}

impl VersionedDao {
    /// Get address for specific tcb_eval_num
    pub fn get_address(&self, tcb_eval_num: u32) -> Result<Address> {
        self.versioned
            .get(&tcb_eval_num)
            .copied()
            .ok_or_else(|| anyhow!("No DAO address for tcbeval {}", tcb_eval_num))
    }
}

/// PCCS contracts - all DAO contracts belong here.
///
/// These contracts provide access to Intel SGX/TDX attestation collaterals
/// stored on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PccsContracts {
    /// Versioned DAO for enclave identity collaterals (QE, TDQE, QVE).
    pub enclave_id_dao: VersionedDao,
    /// Versioned DAO for TCB info collaterals indexed by FMSPC.
    pub fmspc_tcb_dao: VersionedDao,
    /// PCK certificate DAO address.
    pub pck_dao: Address,
    /// PCS certificate and CRL DAO address.
    pub pcs_dao: Address,
    /// TCB evaluation DAO address (v1.1 only).
    pub tcb_eval_dao: Address,
}

/// DCAP contracts - AutomataDcapAttestationFee and PCCSRouter.
///
/// These contracts provide the main attestation verification functionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcapContracts {
    /// AutomataDcapAttestationFee contract address.
    pub dcap_attestation: Address,
    /// PCCSRouter contract address.
    pub pccs_router: Address,
}

/// Static metadata for a DAO deployment on a specific network.
///
/// Contains all contract addresses for both PCCS and DCAP deployments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contracts {
    /// PCCS-related contract addresses.
    pub pccs: PccsContracts,
    /// DCAP-related contract addresses.
    pub dcap: DcapContracts,
}

/// Metadata describing an EVM network supported by Automata DCAP tooling.
///
/// Each network entry contains connection details, contract addresses, and network-specific
/// configuration needed for DCAP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    /// Unique identifier key for this network (e.g., "eth_mainnet", "arbitrum_sepolia").
    pub key: String,
    /// Human-readable display name.
    pub display_name: String,
    /// EVM chain ID.
    pub chain_id: u64,
    /// Indicates whether this network is a testnet (true) or mainnet (false).
    pub testnet: bool,
    /// RPC endpoints ordered by preference. The first entry is used as the default.
    pub rpc_endpoints: Vec<String>,
    /// DCAP deployment version on this network.
    pub version: Version,
    /// Contract addresses for this network deployment.
    pub contracts: Contracts,
    /// Fixed gas-price hints used by legacy flows. TODO: remove once all flows
    /// rely on dynamic gas estimation.
    pub gas_price_hint_wei: Option<u128>,
    /// Block explorer URLs for this network.
    pub block_explorers: Vec<String>,
}

impl Network {
    /// Returns the default RPC URL for this network (the first in the list).
    pub fn default_rpc_url(&self) -> &str {
        &self.rpc_endpoints[0]
    }

    /// Returns the optional gas price hint for this network.
    pub fn gas_price_hint_wei(&self) -> Option<u128> {
        self.gas_price_hint_wei
    }

    /// Async method to resolve contract address with optional TcbEvalDao.standard() call
    pub async fn resolve_contract_address(
        &self,
        contract: ContractKind,
        tcb_eval_num: Option<u32>,
        tcb_id: Option<u8>, // 0 for SGX, 1 for TDX - needed when calling standard()
    ) -> Result<Address> {
        match contract {
            ContractKind::PckDao => Ok(self.contracts.pccs.pck_dao),
            ContractKind::PcsDao => Ok(self.contracts.pccs.pcs_dao),
            ContractKind::TcbEvalDao => {
                // TcbEvalDao only exists in v1.1
                if self.contracts.pccs.tcb_eval_dao.is_zero() {
                    Err(anyhow!("TcbEvalDao not available in v1.0 deployments"))
                } else {
                    Ok(self.contracts.pccs.tcb_eval_dao)
                }
            }
            ContractKind::DcapAttestation => Ok(self.contracts.dcap.dcap_attestation),
            ContractKind::PccsRouter => Ok(self.contracts.dcap.pccs_router),

            ContractKind::EnclaveIdDao | ContractKind::FmspcTcbDao => {
                let versioned_dao = match contract {
                    ContractKind::EnclaveIdDao => &self.contracts.pccs.enclave_id_dao,
                    ContractKind::FmspcTcbDao => &self.contracts.pccs.fmspc_tcb_dao,
                    _ => unreachable!(),
                };

                // Check if this is a v1.0 deployment (has single entry with key 0)
                let is_v1_0 = versioned_dao.versioned.len() == 1 && versioned_dao.versioned.contains_key(&0);

                let eval_num = if is_v1_0 {
                    // v1.0: Use the sentinel value 0 (non-versioned DAO)
                    0
                } else if let Some(num) = tcb_eval_num {
                    // v1.1: Use provided tcb_eval_num
                    num
                } else {
                    // v1.1: Call TcbEvalDao.standard() to get the standard evaluation number
                    if self.contracts.pccs.tcb_eval_dao.is_zero() {
                        return Err(anyhow!("Cannot resolve DAO version: TcbEvalDao not available and tcb_eval_num not provided"));
                    }
                    let tcb_id = tcb_id.ok_or_else(|| anyhow!("tcb_id required when tcb_eval_num is None"))?;
                    self.get_standard_tcb_eval_number(tcb_id).await?
                };

                versioned_dao.get_address(eval_num)
            }
        }
    }

    async fn get_standard_tcb_eval_number(&self, tcb_id: u8) -> Result<u32> {
        use automata_dcap_evm_bindings::r#i_tcb_eval_dao::ITcbEvalDao;

        let rpc_url = self.default_rpc_url().parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tcb_eval_dao = ITcbEvalDao::new(
            self.contracts.pccs.tcb_eval_dao,
            &provider,
        );

        let tcb_eval_number = tcb_eval_dao.standard(tcb_id).call().await?;
        Ok(tcb_eval_number)
    }

    /// Creates an alloy provider from the Network object.
    ///
    /// # Arguments
    /// * `rpc_url` - Optional RPC URL override. If None, uses the network's default RPC URL.
    /// * `private_key` - Optional private key string to create a wallet signer.
    ///                   If None, creates a dummy wallet with a zero key for read-only operations.
    ///
    /// # Returns
    /// A provider with an attached wallet, connected to the specified or default RPC endpoint.
    /// The provider always includes a wallet (dummy if no private_key provided) to ensure
    /// a consistent concrete return type.
    pub fn create_provider(
        &self,
        rpc_url: Option<&str>,
        private_key: Option<&str>,
    ) -> Result<impl Provider> {
        let url = rpc_url.unwrap_or_else(|| self.default_rpc_url());

        // Create wallet: either from provided key or use a dummy key
        let signer: PrivateKeySigner = if let Some(key) = private_key {
            key.parse()?
        } else {
            // Use a minimal valid private key as dummy wallet for read-only operations
            // Private key = 0x0000...0001 (minimal valid ECDSA key)
            let mut dummy_key = [0u8; 32];
            dummy_key[31] = 1;
            PrivateKeySigner::from_slice(&dummy_key)?
        };

        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .with_chain_id(self.chain_id)
            .wallet(wallet)
            .connect_http(url.parse()?);

        Ok(provider)
    }

    /// Extracts the Network from an existing provider by querying its chain ID.
    ///
    /// # Arguments
    /// * `provider` - An existing alloy provider to query.
    /// * `version` - Optional version. If None, uses current/latest version (v1.1)
    ///
    /// # Returns
    /// The Network instance if the provider's chain ID matches a supported network.
    /// Returns an error if the chain ID is not recognized.
    pub async fn from_provider<P: Provider>(
        provider: &P,
        version: Option<Version>,
    ) -> Result<&'static Network> {
        let chain_id = provider.get_chain_id().await?;
        Network::by_chain_id(chain_id, version)
            .ok_or_else(|| anyhow!("Unsupported chain_id: {}", chain_id))
    }
}
