//! Network registry for Automata DCAP on-chain deployments.
//!
//! This crate provides a compile-time embedded registry of all supported blockchain networks
//! and their associated DCAP contract deployments. Network configurations are read from
//! `metadata.toml` and deployment files at compile time, enabling zero-dependency network
//! lookups at runtime.
//!
//! # Usage
//!
//! ```no_run
//! use automata_dcap_network_registry::Network;
//!
//! // Get all registered networks
//! let networks = Network::all(None);
//!
//! // Find network by key
//! let network = Network::by_key("eth_mainnet", None).unwrap();
//!
//! // Find network by chain ID
//! let network = Network::by_chain_id(1, None).unwrap();
//!
//! // Get default network
//! let default = Network::default_network(None).unwrap();
//! ```

use automata_dcap_utils::Version;
use include_dir::{include_dir, Dir};
use std::sync::LazyLock;

// Modules
mod network;
mod parser;

// Re-export public types
pub use network::*;

// Embed deployment files at compile time
static DEPLOYMENT_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/deployment");

// Embed metadata.toml (contains all network definitions)
static METADATA_TOML: &str = include_str!("../metadata.toml");

/// The key for the default network used when no specific network is requested.
///
/// This points to the Automata testnet deployment.
pub const DEFAULT_NETWORK_KEY: &str = "automata_testnet";

// ============================================================================
// Network Registry - Static Storage
// ============================================================================

/// Current/latest version networks (v1.1)
/// When a new version is released, this points to the newest version
static NETWORKS_V1_1: LazyLock<Vec<Network>> = LazyLock::new(|| {
    // NOTE: Current version (v1.1) deployments are in deployment/current/
    // Foundry writes to current/ and build.rs copies historical versions to v1.0/
    if DEPLOYMENT_DIR.get_dir("current").is_some() {
        parser::parse_networks_from_version_dir(METADATA_TOML, &DEPLOYMENT_DIR, "current").ok()
    } else {
        None
    }
    .unwrap_or_else(Vec::new)
});

/// v1.0 networks (legacy support)
static NETWORKS_V1_0: LazyLock<Vec<Network>> = LazyLock::new(|| {
    // NOTE: Due to include_dir quirk, we must use the root DEPLOYMENT_DIR
    // and pass the version subdirectory name to the parser
    if DEPLOYMENT_DIR.get_dir("v1.0").is_some() {
        parser::parse_networks_from_version_dir(METADATA_TOML, &DEPLOYMENT_DIR, "v1.0").ok()
    } else {
        None
    }
    .unwrap_or_else(Vec::new)
});

// ============================================================================
// Network Registry - Public API
// ============================================================================

impl Network {
    /// Returns all registered networks
    ///
    /// # Arguments
    /// * `version` - Optional version. If None, uses current/latest version (v1.1)
    pub fn all(version: Option<Version>) -> &'static [Network] {
        match version.unwrap_or(Version::V1_1) {
            Version::V1_0 => &NETWORKS_V1_0,
            Version::V1_1 => &NETWORKS_V1_1,
        }
    }

    /// Find network by key (e.g., "eth_mainnet", "arbitrum_sepolia")
    ///
    /// # Arguments
    /// * `key` - Network key
    /// * `version` - Optional version. If None, uses current/latest version (v1.1)
    pub fn by_key(key: &str, version: Option<Version>) -> Option<&'static Network> {
        let networks = match version.unwrap_or(Version::V1_1) {
            Version::V1_0 => &NETWORKS_V1_0,
            Version::V1_1 => &NETWORKS_V1_1,
        };

        networks.iter().find(|n| n.key == key)
    }

    /// Find network by chain ID
    ///
    /// # Arguments
    /// * `chain_id` - Chain ID
    /// * `version` - Optional version. If None, uses current/latest version (v1.1)
    pub fn by_chain_id(chain_id: u64, version: Option<Version>) -> Option<&'static Network> {
        let networks = match version.unwrap_or(Version::V1_1) {
            Version::V1_0 => &NETWORKS_V1_0,
            Version::V1_1 => &NETWORKS_V1_1,
        };

        networks.iter().find(|n| n.chain_id == chain_id)
    }

    /// Get the default network (configured in networks.toml)
    ///
    /// # Arguments
    /// * `version` - Optional version. If None, uses current/latest version (v1.1)
    pub fn default_network(version: Option<Version>) -> Option<&'static Network> {
        Network::by_key(DEFAULT_NETWORK_KEY, version)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_all_registry_entries() {
        println!("Total networks defined: {}", Network::all(None).len());

        for network in Network::all(None) {
            // Validate RPC endpoints are non-empty
            assert!(
                !network.rpc_endpoints.is_empty(),
                "Network {} has no RPC endpoints",
                network.key
            );
            for rpc in &network.rpc_endpoints {
                assert!(
                    !rpc.is_empty(),
                    "Network {} has an empty RPC endpoint",
                    network.key
                );
            }

            // Validate PCCS contract addresses are non-zero
            assert!(
                !network.contracts.pccs.pck_dao.is_zero(),
                "Network {} has zero address for pck_dao",
                network.key
            );
            assert!(
                !network.contracts.pccs.pcs_dao.is_zero(),
                "Network {} has zero address for pcs_dao",
                network.key
            );
            assert!(
                !network.contracts.pccs.tcb_eval_dao.is_zero(),
                "Network {} has zero address for tcb_eval_dao",
                network.key
            );

            // Validate versioned DAOs have at least one version and all are non-zero
            assert!(
                !network.contracts.pccs.enclave_id_dao.versioned.is_empty(),
                "Network {} has no enclave_id_dao versions",
                network.key
            );
            for (ver, addr) in &network.contracts.pccs.enclave_id_dao.versioned {
                assert!(
                    !addr.is_zero(),
                    "Network {} has zero address for enclave_id_dao version {}",
                    network.key,
                    ver
                );
            }

            assert!(
                !network.contracts.pccs.fmspc_tcb_dao.versioned.is_empty(),
                "Network {} has no fmspc_tcb_dao versions",
                network.key
            );
            for (ver, addr) in &network.contracts.pccs.fmspc_tcb_dao.versioned {
                assert!(
                    !addr.is_zero(),
                    "Network {} has zero address for fmspc_tcb_dao version {}",
                    network.key,
                    ver
                );
            }

            // Validate DCAP contracts
            assert!(
                !network.contracts.dcap.dcap_attestation.is_zero(),
                "Network {} has zero address for dcap_attestation",
                network.key
            );
            assert!(
                !network.contracts.dcap.pccs_router.is_zero(),
                "Network {} has zero address for pccs_router",
                network.key
            );

            // Validate chain ID is non-zero
            assert!(
                network.chain_id > 0,
                "Network {} has zero chain ID",
                network.key
            );

            // Validate display name is non-empty
            assert!(
                !network.display_name.is_empty(),
                "Network {} has empty display name",
                network.key
            );

            // Validate key is non-empty
            assert!(!network.key.is_empty(), "Found network with empty key");
        }
    }

    #[test]
    fn validate_unique_keys() {
        let mut keys = std::collections::HashSet::new();
        for network in Network::all(None) {
            assert!(
                keys.insert(&network.key),
                "Duplicate network key: {}",
                network.key
            );
        }
    }

    #[test]
    fn validate_unique_chain_ids() {
        let mut chain_ids = std::collections::HashSet::new();
        for network in Network::all(None) {
            assert!(
                chain_ids.insert(network.chain_id),
                "Duplicate chain ID {} for network {}",
                network.chain_id,
                network.key
            );
        }
    }

    #[test]
    fn validate_default_network_exists() {
        let default = Network::default_network(None);
        assert!(default.is_some(), "Default network should exist");
        assert_eq!(default.unwrap().key, DEFAULT_NETWORK_KEY);
    }
}
