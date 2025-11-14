use crate::network::*;
use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use automata_dcap_utils::Version;
use include_dir::Dir;
use serde::Deserialize;
use std::{collections::HashMap, str::FromStr};

/// Network metadata from TOML config
#[derive(Debug, Deserialize)]
struct NetworkMetadata {
    name: String,
    chain_id: u64,
    testnet: bool,
    rpc_endpoints: Vec<String>,
    #[serde(deserialize_with = "deserialize_u128_from_i64_or_string")]
    #[serde(default)]
    gas_price_hint_wei: Option<u128>,
    block_explorers: Vec<String>,
}

/// Custom deserializer for u128 from TOML (which only supports i64)
fn deserialize_u128_from_i64_or_string<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Deserialize};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U128OrString {
        Int(i64),
        String(String),
    }

    match Option::<U128OrString>::deserialize(deserializer)? {
        None => Ok(None),
        Some(U128OrString::Int(i)) => {
            if i < 0 {
                return Err(de::Error::custom(format!("negative gas price: {}", i)));
            }
            Ok(Some(i as u128))
        }
        Some(U128OrString::String(s)) => {
            let val = s.parse::<u128>().map_err(de::Error::custom)?;
            Ok(Some(val))
        }
    }
}

/// Parse networks from a version-specific deployment directory
/// Scans all chain_id subdirectories and loads metadata for each
pub(crate) fn parse_networks_from_version_dir(
    metadata_toml: &str,
    deployment_dir: &Dir,
    version: &str,
) -> Result<Vec<Network>> {
    // Parse metadata.toml (all network definitions)
    let metadata_config: HashMap<String, toml::Value> = toml::from_str(metadata_toml)?;

    // Create a chain_id -> (key, metadata) lookup map
    let mut chain_id_to_metadata: HashMap<u64, (String, NetworkMetadata)> = HashMap::new();
    for (key, value) in &metadata_config {
        if let Ok(metadata) = value.clone().try_into::<NetworkMetadata>() {
            chain_id_to_metadata.insert(metadata.chain_id, (key.clone(), metadata));
        }
    }

    let mut networks = Vec::new();

    // Get the version-specific directory
    let version_dir = deployment_dir
        .get_dir(version)
        .ok_or_else(|| anyhow!("Version directory {} not found", version))?;

    // Scan all subdirectories in the version directory
    for entry in version_dir.dirs() {
        // Try to parse directory name as chain_id
        if let Some(dir_name) = entry.path().file_name().and_then(|n| n.to_str()) {
            if let Ok(chain_id) = dir_name.parse::<u64>() {
                // Check if we have metadata for this chain_id
                if let Some((key, metadata)) = chain_id_to_metadata.get(&chain_id) {
                    // Parse deployment JSON files for this chain_id
                    match parse_deployment_for_chain(&chain_id, deployment_dir, version) {
                        Ok(contracts) => {
                            networks.push(Network {
                                key: key.clone(),
                                display_name: metadata.name.clone(),
                                chain_id: metadata.chain_id,
                                testnet: metadata.testnet,
                                rpc_endpoints: metadata.rpc_endpoints.clone(),
                                version: Version::from_str(version)?,
                                contracts,
                                gas_price_hint_wei: metadata.gas_price_hint_wei,
                                block_explorers: metadata.block_explorers.clone(),
                            });
                        }
                        Err(e) => {
                            eprintln!(
                                "Warning: Skipping network '{}' (chain_id {}, version {}): {}",
                                key, chain_id, version, e
                            );
                        }
                    }
                } else {
                    // Chain ID found in deployment but no metadata - just skip it silently
                    // (warning is already issued by build.rs)
                }
            }
        }
    }

    // Sort by chain_id for consistent ordering
    networks.sort_by_key(|n| n.chain_id);

    Ok(networks)
}

/// Parse deployment JSON files for a specific chain ID
fn parse_deployment_for_chain(
    chain_id: &u64,
    deployment_dir: &Dir,
    version: &str,
) -> Result<Contracts> {
    let chain_id_str = chain_id.to_string();
    // Construct the full path: version/chain_id (e.g., "v1.1/1398243")
    let chain_path = format!("{}/{}", version, chain_id_str);
    let chain_dir = deployment_dir
        .get_dir(&chain_path)
        .ok_or_else(|| anyhow!("No deployment directory for chain_id {}", chain_id))?;

    // Find onchain_pccs.json file
    let pccs_file = chain_dir
        .files()
        .find(|f| f.path().file_name().and_then(|n| n.to_str()) == Some("onchain_pccs.json"))
        .ok_or_else(|| anyhow!("Missing onchain_pccs.json"))?;
    let pccs_json: serde_json::Value = serde_json::from_str(
        pccs_file
            .contents_utf8()
            .ok_or_else(|| anyhow!("Invalid UTF-8 in onchain_pccs.json"))?,
    )?;

    // Find dcap.json file
    let dcap_file = chain_dir
        .files()
        .find(|f| f.path().file_name().and_then(|n| n.to_str()) == Some("dcap.json"))
        .ok_or_else(|| anyhow!("Missing dcap.json"))?;
    let dcap_json: serde_json::Value = serde_json::from_str(
        dcap_file
            .contents_utf8()
            .ok_or_else(|| anyhow!("Invalid UTF-8 in dcap.json"))?,
    )?;

    // Parse PCCS contracts based on version
    let pccs = parse_pccs_contracts(&pccs_json, version)?;

    // Parse DCAP contracts
    let dcap = parse_dcap_contracts(&dcap_json)?;

    Ok(Contracts { pccs, dcap })
}

/// Parse PCCS contracts from JSON
fn parse_pccs_contracts(json: &serde_json::Value, version: &str) -> Result<PccsContracts> {
    let mut enclave_id_versioned = HashMap::new();
    let mut fmspc_tcb_versioned = HashMap::new();

    // Determine if this version uses versioned DAOs by parsing the version string
    // This uses the Version enum which is auto-generated from version.toml
    let uses_versioned = Version::from_str(version)
        .map(|v| v.uses_versioned_daos())
        .unwrap_or(false); // Default to v1.0 behavior if version can't be parsed

    if let Some(obj) = json.as_object() {
        if uses_versioned {
            // v1.1: Parse versioned DAOs
            for (key, value) in obj {
                if let Some(num_str) =
                    key.strip_prefix("AutomataEnclaveIdentityDaoVersioned_tcbeval_")
                {
                    if let Ok(num) = num_str.parse::<u32>() {
                        let addr: Address = value
                            .as_str()
                            .ok_or_else(|| anyhow!("Invalid address string"))?
                            .parse()?;
                        enclave_id_versioned.insert(num, addr);
                    }
                }
                if let Some(num_str) = key.strip_prefix("AutomataFmspcTcbDaoVersioned_tcbeval_") {
                    if let Ok(num) = num_str.parse::<u32>() {
                        let addr: Address = value
                            .as_str()
                            .ok_or_else(|| anyhow!("Invalid address string"))?
                            .parse()?;
                        fmspc_tcb_versioned.insert(num, addr);
                    }
                }
            }

            // v1.1 must have TcbEvalDao
            if !json.get("AutomataTcbEvalDao").is_some() {
                return Err(anyhow!("v1.1 deployment missing AutomataTcbEvalDao"));
            }
        } else {
            // v1.0: Use non-versioned DAOs - create a single entry with tcbeval_num = 0
            // This allows the same VersionedDao structure to work for both versions
            let enclave_id_addr: Address = json["AutomataEnclaveIdentityDao"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing AutomataEnclaveIdentityDao in v1.0 deployment"))?
                .parse()?;
            let fmspc_tcb_addr: Address = json["AutomataFmspcTcbDao"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing AutomataFmspcTcbDao in v1.0 deployment"))?
                .parse()?;

            // Use a sentinel value (0) for non-versioned DAOs
            enclave_id_versioned.insert(0, enclave_id_addr);
            fmspc_tcb_versioned.insert(0, fmspc_tcb_addr);
        }
    }

    // Parse TcbEvalDao (only exists in versions that use versioned DAOs)
    let tcb_eval_dao = if uses_versioned {
        json["AutomataTcbEvalDao"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing AutomataTcbEvalDao"))?
            .parse()?
    } else {
        // v1.0 doesn't have TcbEvalDao, use zero address
        Address::ZERO
    };

    Ok(PccsContracts {
        enclave_id_dao: VersionedDao {
            versioned: enclave_id_versioned,
        },
        fmspc_tcb_dao: VersionedDao {
            versioned: fmspc_tcb_versioned,
        },
        pck_dao: json["AutomataPckDao"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing AutomataPckDao"))?
            .parse()?,
        pcs_dao: json["AutomataPcsDao"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing AutomataPcsDao"))?
            .parse()?,
        tcb_eval_dao,
    })
}

/// Parse DCAP contracts from JSON
fn parse_dcap_contracts(json: &serde_json::Value) -> Result<DcapContracts> {
    Ok(DcapContracts {
        dcap_attestation: json["AutomataDcapAttestationFee"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing AutomataDcapAttestationFee"))?
            .parse()?,
        pccs_router: json["PCCSRouter"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing PCCSRouter"))?
            .parse()?,
    })
}
