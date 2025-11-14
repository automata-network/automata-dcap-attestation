use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Version configuration from version.toml
#[derive(Debug, serde::Deserialize)]
struct VersionToml {
    metadata: Metadata,
    versions: HashMap<String, VersionConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct Metadata {
    supported: Vec<String>,
    #[serde(default)]
    current: String,
}

#[derive(Debug, serde::Deserialize)]
struct VersionConfig {
    name: String,
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    deployment_url: String,
}

/// Network metadata from metadata.toml (for DEPLOYMENT.md generation)
#[derive(Debug, serde::Deserialize)]
struct NetworkMetadata {
    name: String,
    chain_id: u64,
    testnet: bool,
    block_explorers: Vec<String>,
}

/// Deployment information for a single network
#[derive(Debug)]
struct DeploymentInfo {
    chain_id: u64,
    network_name: String,
    #[allow(dead_code)]
    network_key: String,
    testnet: bool,
    block_explorer: String, // First block explorer URL
    pccs_contracts: PccsContracts,
    dcap_contracts: DcapContracts,
}

/// PCCS contract addresses
#[derive(Debug)]
struct PccsContracts {
    pck_dao: String,
    pcs_dao: String,
    // v1.0: single entry
    enclave_id_dao: Option<String>,
    fmspc_tcb_dao: Option<String>,
    // v1.1: versioned DAOs
    enclave_id_versioned: HashMap<u32, String>, // tcbeval_num -> address
    fmspc_tcb_versioned: HashMap<u32, String>,  // tcbeval_num -> address
    tcb_eval_dao: Option<String>,
}

/// DCAP contract addresses
#[derive(Debug)]
struct DcapContracts {
    dcap_attestation: String,
    pccs_router: String,
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=metadata.toml");
    println!("cargo:rerun-if-changed=deployment");
    println!("cargo:rerun-if-changed=../../version.toml");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let manifest_path = PathBuf::from(&manifest_dir);
    let deployment_dest = manifest_path.join("deployment");

    // Parse version.toml from workspace root
    let version_toml_path = manifest_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("version.toml"))
        .ok_or_else(|| anyhow::anyhow!("Could not find workspace root"))?;

    let version_toml_content = fs::read_to_string(&version_toml_path)?;
    let version_config: VersionToml = toml::from_str(&version_toml_content)?;

    eprintln!("\n=== Processing deployment files ===");

    // Create cache directory for hash files
    let cache_dir = deployment_dest.join("cache");
    fs::create_dir_all(&cache_dir)?;

    // Process each version
    for version_key in &version_config.metadata.supported {
        let version_info = version_config
            .versions
            .get(&version_key.replace(".", "_"))
            .ok_or_else(|| anyhow::anyhow!("Version {} not found in version.toml", version_key))?;

        eprintln!("\n--- Processing {} ---", version_info.name);

        // Check if this is the current version
        let is_current = version_key == &version_config.metadata.current;

        // Determine deployment source
        let deployment_src = if is_current {
            // Current version always uses deployment/current/
            let local_path = manifest_path.join("deployment/current");
            if !local_path.exists() {
                anyhow::bail!(
                    "Current version {} requires deployment/current/ directory, but it does not exist at: {}",
                    version_key,
                    local_path.display()
                );
            }
            eprintln!("  Using current deployment: deployment/current/");
            local_path
        } else if !version_info.deployment_url.is_empty() {
            // Fetch from URL or local absolute path
            if version_info.deployment_url.starts_with("http://")
                || version_info.deployment_url.starts_with("https://") {
                download_from_url(&version_info.deployment_url)?
            } else {
                // Treat as local path
                let local_path = PathBuf::from(&version_info.deployment_url);
                if !local_path.exists() {
                    anyhow::bail!(
                        "Local deployment path does not exist: {}",
                        version_info.deployment_url
                    );
                }
                eprintln!("  Using local path: {}", version_info.deployment_url);
                local_path
            }
        } else {
            // Check if deployment directory already exists
            let version_dest = deployment_dest.join(version_key);
            if !version_dest.exists() {
                anyhow::bail!(
                    "No deployment_url specified for {} and deployment/{} directory is missing. \
                    Please provide a deployment_url in version.toml or ensure deployment/{} exists.",
                    version_info.name,
                    version_key,
                    version_key
                );
            }
            eprintln!("  ⚠ No deployment source specified, using existing deployment/{}", version_key);
            continue;
        };

        // Load metadata to check which chain IDs have metadata defined
        let metadata_path = manifest_path.join("metadata.toml");
        let metadata_chain_ids = parse_metadata_chain_ids(&metadata_path)?;

        // Scan deployment source for all chain IDs and check metadata
        let (fetched_hash, found_chain_ids, missing_metadata_chain_ids) =
            calculate_deployment_hash(&deployment_src, &metadata_chain_ids)?;

        eprintln!("  Fetched deployment hash: {}", hex::encode(&fetched_hash));

        // Warn about chain IDs found in source but missing metadata
        // Only show warnings for current version to reduce noise
        if !missing_metadata_chain_ids.is_empty() && is_current {
            eprintln!("  ⚠ Warning: {} chain IDs found in deployment source but missing metadata:", missing_metadata_chain_ids.len());
            for chain_id in &missing_metadata_chain_ids {
                eprintln!("    - Chain ID: {}", chain_id);
            }
            eprintln!("  ℹ️  Add these chain IDs to metadata.toml to include them in deployments");
        }

        eprintln!("  Found {} networks in deployment", found_chain_ids.len());

        if is_current {
            // For current version, just generate DEPLOYMENT.md in the current directory
            // No need to copy - Foundry writes directly to deployment/current/
            eprintln!("  → Generating DEPLOYMENT.md for current version...");
            generate_deployment_md(&deployment_src, "current", &metadata_path)?;
        } else {
            // For historical versions, check if we need to update
            let version_dest = deployment_dest.join(version_key);
            let hash_file_path = cache_dir.join(format!(".deployment-hash-{}", version_key));

            // Check if destination exists and hash matches
            let stored_hash = if hash_file_path.exists() {
                fs::read(&hash_file_path).ok()
            } else {
                None
            };

            let needs_update = if !version_dest.exists() {
                // Always update if destination doesn't exist
                eprintln!("  → Deployment directory missing, fetching...");
                true
            } else {
                match stored_hash {
                    Some(ref stored) if stored == &fetched_hash => {
                        eprintln!("  ✓ Deployment unchanged, skipping copy");
                        false
                    }
                    _ => {
                        eprintln!("  → Deployment changed, updating...");
                        true
                    }
                }
            };

            if needs_update {
                // Create version-specific deployment directory
                if version_dest.exists() {
                    fs::remove_dir_all(&version_dest)?;
                }
                fs::create_dir_all(&version_dest)?;

                // Copy all chain IDs found in source that have metadata
                let count = copy_deployments(&deployment_src, &version_dest, &metadata_chain_ids)?;

                eprintln!("  ✓ Copied {} networks", count);

                // Store new hash
                fs::write(&hash_file_path, &fetched_hash)?;
                eprintln!("  ✓ Updated hash file");

                // Generate DEPLOYMENT.md
                generate_deployment_md(&version_dest, version_key, &metadata_path)?;
            }
        }
    }

    eprintln!("\n✓ Deployment processing complete\n");

    Ok(())
}

/// Calculate SHA256 hash of all chain IDs in deployment that have metadata
/// Returns (hash, found_chain_ids_with_metadata, chain_ids_without_metadata)
fn calculate_deployment_hash(
    dir: &Path,
    metadata_chain_ids: &HashSet<u64>,
) -> anyhow::Result<(Vec<u8>, HashSet<u64>, Vec<u64>)> {
    let mut hasher = Sha256::new();
    let mut files = Vec::new();
    let mut found_chain_ids_with_metadata = HashSet::new();
    let mut chain_ids_without_metadata = Vec::new();

    // Scan all chain ID directories in the deployment source
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(chain_id_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(chain_id) = chain_id_str.parse::<u64>() {
                    let onchain_pccs_file = path.join("onchain_pccs.json");
                    let dcap_file = path.join("dcap.json");

                    // Check if both JSON files exist
                    if onchain_pccs_file.exists() && dcap_file.exists() {
                        // Check if this chain ID has metadata
                        if metadata_chain_ids.contains(&chain_id) {
                            found_chain_ids_with_metadata.insert(chain_id);

                            // Collect JSON files from this chain ID directory
                            for sub_entry in fs::read_dir(&path)? {
                                let sub_entry = sub_entry?;
                                let sub_path = sub_entry.path();
                                if sub_path.extension().and_then(|s| s.to_str()) == Some("json") {
                                    files.push(sub_path);
                                }
                            }
                        } else {
                            // Found in deployment but missing metadata
                            chain_ids_without_metadata.push(chain_id);
                        }
                    }
                }
            }
        }
    }

    // Sort for consistent output
    chain_ids_without_metadata.sort();

    // Sort files for deterministic hashing
    files.sort();

    // Hash all file contents
    for file in files {
        let content = fs::read(&file)?;
        hasher.update(&content);
    }

    Ok((
        hasher.finalize().to_vec(),
        found_chain_ids_with_metadata,
        chain_ids_without_metadata,
    ))
}

/// Copy deployments for chain IDs that have metadata
fn copy_deployments(
    src: &Path,
    dst: &Path,
    metadata_chain_ids: &HashSet<u64>,
) -> anyhow::Result<usize> {
    let mut count = 0;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(chain_id_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(chain_id) = chain_id_str.parse::<u64>() {
                    let onchain_pccs_file = path.join("onchain_pccs.json");
                    let dcap_file = path.join("dcap.json");

                    // Check if both JSON files exist
                    if onchain_pccs_file.exists() && dcap_file.exists() {
                        // Only copy if this chain ID has metadata
                        if metadata_chain_ids.contains(&chain_id) {
                            // Copy the directory
                            let dest_dir = dst.join(chain_id.to_string());
                            copy_dir_recursive(&path, &dest_dir)?;
                            count += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Download deployment files from a GitHub URL to a temporary directory
fn download_from_url(url: &str) -> anyhow::Result<PathBuf> {
    if !url.contains("github.com") {
        anyhow::bail!("Only GitHub URLs are supported. URL: {}", url);
    }

    eprintln!("  Downloading from: {}", url);

    // Parse GitHub URL
    // Format: https://github.com/{owner}/{repo}/tree/{ref}/{path}
    let (owner, repo, git_ref, subpath) = parse_github_url(url)?;

    // Download tarball from GitHub
    let tarball_url = format!(
        "https://github.com/{}/{}/archive/{}.tar.gz",
        owner, repo, git_ref
    );

    let response = reqwest::blocking::get(&tarball_url)
        .map_err(|e| anyhow::anyhow!("Failed to download tarball: {}", e))?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download tarball: HTTP {}", response.status());
    }

    // Create temporary directory
    let temp_dir = env::temp_dir().join(format!("dcap-deployment-{}", std::process::id()));
    fs::create_dir_all(&temp_dir)?;

    // Extract tarball
    let tar_gz = response
        .bytes()
        .map_err(|e| anyhow::anyhow!("Failed to read tarball: {}", e))?;
    let tar = flate2::read::GzDecoder::new(&tar_gz[..]);
    let mut archive = tar::Archive::new(tar);

    archive.unpack(&temp_dir)?;

    // Find the extracted directory
    let extracted_dir = find_extracted_directory(&temp_dir, &repo)?;

    // If a subpath was specified, append it
    let deployment_path = if let Some(subpath) = subpath {
        extracted_dir.join(subpath)
    } else {
        extracted_dir
    };

    if !deployment_path.exists() {
        anyhow::bail!(
            "Deployment path not found in archive: {}",
            deployment_path.display()
        );
    }

    Ok(deployment_path)
}

/// Parse GitHub URL to extract owner, repo, ref, and optional subpath
fn parse_github_url(url: &str) -> anyhow::Result<(String, String, String, Option<String>)> {
    // Expected format: https://github.com/{owner}/{repo}/tree/{ref}/{path}
    let url = url.trim_end_matches('/');

    let parts: Vec<&str> = if url.contains("/tree/") {
        let after_github = url
            .strip_prefix("https://github.com/")
            .or_else(|| url.strip_prefix("http://github.com/"))
            .ok_or_else(|| anyhow::anyhow!("Invalid GitHub URL"))?;

        after_github.split('/').collect()
    } else {
        anyhow::bail!("GitHub URL must contain '/tree/' to specify a branch/tag");
    };

    if parts.len() < 4 {
        anyhow::bail!(
            "Invalid GitHub URL format. Expected: https://github.com/owner/repo/tree/ref[/path]"
        );
    }

    let owner = parts[0].to_string();
    let repo = parts[1].to_string();
    // Skip "tree" at index 2
    let git_ref = parts[3].to_string();

    // Everything after the ref is the subpath
    let subpath = if parts.len() > 4 {
        Some(parts[4..].join("/"))
    } else {
        None
    };

    Ok((owner, repo, git_ref, subpath))
}

/// Find the extracted directory in the temp directory
fn find_extracted_directory(temp_dir: &Path, repo: &str) -> anyhow::Result<PathBuf> {
    // The extracted directory is typically named: {repo}-{ref} or {repo}-{ref-sanitized}
    // Find the first directory that starts with the repo name
    for entry in fs::read_dir(temp_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(repo) {
                    return Ok(path);
                }
            }
        }
    }

    anyhow::bail!("Could not find extracted directory for repo: {}", repo)
}

/// Parse metadata.toml and extract all chain IDs
fn parse_metadata_chain_ids(metadata_toml_path: &Path) -> anyhow::Result<HashSet<u64>> {
    let metadata_content = fs::read_to_string(metadata_toml_path)?;
    let metadata_config: HashMap<String, toml::Value> = toml::from_str(&metadata_content)?;

    let mut chain_ids = HashSet::new();

    // Extract chain_id from each network definition
    for (_key, value) in metadata_config {
        if let Some(table) = value.as_table() {
            if let Some(chain_id_value) = table.get("chain_id") {
                if let Some(chain_id) = chain_id_value.as_integer() {
                    chain_ids.insert(chain_id as u64);
                }
            }
        }
    }

    Ok(chain_ids)
}

/// Generate DEPLOYMENT.md for a version
fn generate_deployment_md(
    version_dest: &Path,
    version: &str,
    metadata_path: &Path,
) -> anyhow::Result<()> {
    let deployments = collect_deployment_info(version_dest, metadata_path, version)?;

    if deployments.is_empty() {
        eprintln!("  ⚠ No deployments found, skipping DEPLOYMENT.md generation");
        return Ok(());
    }

    // Only v1.0 uses non-versioned DAOs, all other versions use versioned DAOs
    let is_v1_0 = version == "v1.0";
    let mut md = String::new();

    // Header
    md.push_str(&format!("# Automata DCAP Deployment ({})\n\n", version));

    // Section 1: Automata Onchain PCCS (Non-versioned)
    md.push_str("## Automata Onchain PCCS\n\n");

    // Separate testnet and mainnet
    let testnets: Vec<_> = deployments.iter().filter(|d| d.testnet).collect();
    let mainnets: Vec<_> = deployments.iter().filter(|d| !d.testnet).collect();

    // AutomataPckDao
    md.push_str("### AutomataPckDao\n\n");

    if !testnets.is_empty() {
        md.push_str("#### Testnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &testnets {
            let addr_link = format_address_link(&d.pccs_contracts.pck_dao, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    if !mainnets.is_empty() {
        md.push_str("#### Mainnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &mainnets {
            let addr_link = format_address_link(&d.pccs_contracts.pck_dao, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    // AutomataPcsDao
    md.push_str("### AutomataPcsDao\n\n");

    if !testnets.is_empty() {
        md.push_str("#### Testnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &testnets {
            let addr_link = format_address_link(&d.pccs_contracts.pcs_dao, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    if !mainnets.is_empty() {
        md.push_str("#### Mainnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &mainnets {
            let addr_link = format_address_link(&d.pccs_contracts.pcs_dao, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    // v1.0 ONLY: AutomataEnclaveIdentityDao and AutomataFmspcTcbDao (non-versioned)
    if is_v1_0 {
        // AutomataEnclaveIdentityDao
        md.push_str("### AutomataEnclaveIdentityDao\n\n");

        if !testnets.is_empty() {
            md.push_str("#### Testnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &testnets {
                if let Some(addr) = &d.pccs_contracts.enclave_id_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }

        if !mainnets.is_empty() {
            md.push_str("#### Mainnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &mainnets {
                if let Some(addr) = &d.pccs_contracts.enclave_id_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }

        // AutomataFmspcTcbDao
        md.push_str("### AutomataFmspcTcbDao\n\n");

        if !testnets.is_empty() {
            md.push_str("#### Testnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &testnets {
                if let Some(addr) = &d.pccs_contracts.fmspc_tcb_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }

        if !mainnets.is_empty() {
            md.push_str("#### Mainnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &mainnets {
                if let Some(addr) = &d.pccs_contracts.fmspc_tcb_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }
    }

    // Section 2: Versioned DAOs (all versions EXCEPT v1.0)
    if !is_v1_0 {
        md.push_str("---\n\n");
        md.push_str("<details>\n<summary>\n\n");
        md.push_str("## Automata Onchain PCCS (Versioned DAOs)\n\n");
        md.push_str("</summary>\n\n");

        // AutomataTcbEvalDao
        md.push_str("### AutomataTcbEvalDao\n\n");

        if testnets.iter().any(|d| d.pccs_contracts.tcb_eval_dao.is_some()) {
            md.push_str("#### Testnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &testnets {
                if let Some(addr) = &d.pccs_contracts.tcb_eval_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }

        if mainnets.iter().any(|d| d.pccs_contracts.tcb_eval_dao.is_some()) {
            md.push_str("#### Mainnet\n\n");
            md.push_str("| Network | Address |\n");
            md.push_str("|---------|----------|\n");
            for d in &mainnets {
                if let Some(addr) = &d.pccs_contracts.tcb_eval_dao {
                    let addr_link = format_address_link(addr, &d.block_explorer);
                    md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                }
            }
            md.push_str("\n");
        }

        // Collect all TCB eval numbers
        let mut tcb_eval_nums: HashSet<u32> = HashSet::new();
        for d in &deployments {
            tcb_eval_nums.extend(d.pccs_contracts.enclave_id_versioned.keys());
            tcb_eval_nums.extend(d.pccs_contracts.fmspc_tcb_versioned.keys());
        }
        let mut tcb_eval_nums: Vec<u32> = tcb_eval_nums.into_iter().collect();
        tcb_eval_nums.sort();

        // AutomataEnclaveIdentityDaoVersioned
        md.push_str("### AutomataEnclaveIdentityDaoVersioned\n\n");

        for tcb_num in &tcb_eval_nums {
            md.push_str(&format!("#### TCB Evaluation Data Number {}\n\n", tcb_num));

            // Testnet
            let has_testnet = testnets.iter().any(|d| {
                d.pccs_contracts.enclave_id_versioned.contains_key(tcb_num)
            });

            if has_testnet {
                md.push_str("##### Testnet\n\n");
                md.push_str("| Network | Address |\n");
                md.push_str("|---------|----------|\n");

                for d in &testnets {
                    if let Some(addr) = d.pccs_contracts.enclave_id_versioned.get(tcb_num) {
                        let addr_link = format_address_link(addr, &d.block_explorer);
                        md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                    }
                }

                md.push_str("\n");
            }

            // Mainnet
            let has_mainnet = mainnets.iter().any(|d| {
                d.pccs_contracts.enclave_id_versioned.contains_key(tcb_num)
            });

            if has_mainnet {
                md.push_str("##### Mainnet\n\n");
                md.push_str("| Network | Address |\n");
                md.push_str("|---------|----------|\n");

                for d in &mainnets {
                    if let Some(addr) = d.pccs_contracts.enclave_id_versioned.get(tcb_num) {
                        let addr_link = format_address_link(addr, &d.block_explorer);
                        md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                    }
                }

                md.push_str("\n");
            }
        }

        // AutomataFmspcTcbDaoVersioned
        md.push_str("### AutomataFmspcTcbDaoVersioned\n\n");

        for tcb_num in &tcb_eval_nums {
            md.push_str(&format!("#### TCB Evaluation Data Number {}\n\n", tcb_num));

            // Testnet
            let has_testnet = testnets.iter().any(|d| {
                d.pccs_contracts.fmspc_tcb_versioned.contains_key(tcb_num)
            });

            if has_testnet {
                md.push_str("##### Testnet\n\n");
                md.push_str("| Network | Address |\n");
                md.push_str("|---------|----------|\n");

                for d in &testnets {
                    if let Some(addr) = d.pccs_contracts.fmspc_tcb_versioned.get(tcb_num) {
                        let addr_link = format_address_link(addr, &d.block_explorer);
                        md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                    }
                }

                md.push_str("\n");
            }

            // Mainnet
            let has_mainnet = mainnets.iter().any(|d| {
                d.pccs_contracts.fmspc_tcb_versioned.contains_key(tcb_num)
            });

            if has_mainnet {
                md.push_str("##### Mainnet\n\n");
                md.push_str("| Network | Address |\n");
                md.push_str("|---------|----------|\n");

                for d in &mainnets {
                    if let Some(addr) = d.pccs_contracts.fmspc_tcb_versioned.get(tcb_num) {
                        let addr_link = format_address_link(addr, &d.block_explorer);
                        md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
                    }
                }

                md.push_str("\n");
            }
        }

        // Close collapsible section
        md.push_str("</details>\n\n");
    }

    // Section 3: Automata DCAP Verifiers
    md.push_str("---\n\n");
    md.push_str("## Automata DCAP Verifiers\n\n");

    // AutomataDcapAttestationFee
    md.push_str("### AutomataDcapAttestationFee\n\n");

    if !testnets.is_empty() {
        md.push_str("#### Testnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &testnets {
            let addr_link = format_address_link(&d.dcap_contracts.dcap_attestation, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    if !mainnets.is_empty() {
        md.push_str("#### Mainnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &mainnets {
            let addr_link = format_address_link(&d.dcap_contracts.dcap_attestation, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    // PCCSRouter
    md.push_str("### PCCSRouter\n\n");

    if !testnets.is_empty() {
        md.push_str("#### Testnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &testnets {
            let addr_link = format_address_link(&d.dcap_contracts.pccs_router, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    if !mainnets.is_empty() {
        md.push_str("#### Mainnet\n\n");
        md.push_str("| Network | Address |\n");
        md.push_str("|---------|----------|\n");
        for d in &mainnets {
            let addr_link = format_address_link(&d.dcap_contracts.pccs_router, &d.block_explorer);
            md.push_str(&format!("| {} | {} |\n", d.network_name, addr_link));
        }
        md.push_str("\n");
    }

    // Write to file
    let md_path = version_dest.join("DEPLOYMENT.md");
    fs::write(&md_path, md)?;
    eprintln!("  ✓ Generated DEPLOYMENT.md");

    Ok(())
}

/// Format address as markdown link to block explorer
fn format_address_link(address: &str, block_explorer: &str) -> String {
    if block_explorer.is_empty() {
        return address.to_string();
    }
    let explorer_url = format!("{}/address/{}", block_explorer.trim_end_matches('/'), address);
    format!("[{}]({})", address, explorer_url)
}

/// Collect deployment information from all networks in a version directory
fn collect_deployment_info(
    version_dest: &Path,
    metadata_path: &Path,
    version: &str,
) -> anyhow::Result<Vec<DeploymentInfo>> {
    // Load metadata.toml
    let metadata_content = fs::read_to_string(metadata_path)?;
    let metadata_config: HashMap<String, toml::Value> = toml::from_str(&metadata_content)?;

    // Create chain_id -> (key, metadata) lookup map
    let mut chain_id_to_metadata: HashMap<u64, (String, NetworkMetadata)> = HashMap::new();
    for (key, value) in &metadata_config {
        if key == "default" {
            continue; // Skip default config
        }
        if let Ok(metadata) = value.clone().try_into::<NetworkMetadata>() {
            chain_id_to_metadata.insert(metadata.chain_id, (key.clone(), metadata));
        }
    }

    let mut deployments = Vec::new();
    let is_v1_0 = version == "v1.0";

    // Scan all chain_id directories
    for entry in fs::read_dir(version_dest)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(chain_id_str) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(chain_id) = chain_id_str.parse::<u64>() {
                    // Get metadata for this chain_id
                    if let Some((network_key, metadata)) = chain_id_to_metadata.get(&chain_id) {
                        let onchain_pccs_file = path.join("onchain_pccs.json");
                        let dcap_file = path.join("dcap.json");

                        if onchain_pccs_file.exists() && dcap_file.exists() {
                            // Parse onchain_pccs.json
                            let pccs_content = fs::read_to_string(&onchain_pccs_file)?;
                            let pccs_json: serde_json::Value = serde_json::from_str(&pccs_content)?;

                            // Parse dcap.json
                            let dcap_content = fs::read_to_string(&dcap_file)?;
                            let dcap_json: serde_json::Value = serde_json::from_str(&dcap_content)?;

                            // Extract PCCS contracts
                            let mut enclave_id_versioned = HashMap::new();
                            let mut fmspc_tcb_versioned = HashMap::new();
                            let mut enclave_id_dao = None;
                            let mut fmspc_tcb_dao = None;
                            let mut tcb_eval_dao = None;

                            if let Some(obj) = pccs_json.as_object() {
                                if is_v1_0 {
                                    // v1.0 ONLY: Parse non-versioned DAOs
                                    enclave_id_dao = obj.get("AutomataEnclaveIdentityDao")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    fmspc_tcb_dao = obj.get("AutomataFmspcTcbDao")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                } else {
                                    // All other versions: Parse versioned DAOs and TcbEvalDao
                                    for (key, value) in obj {
                                        if let Some(num_str) = key.strip_prefix("AutomataEnclaveIdentityDaoVersioned_tcbeval_") {
                                            if let Ok(num) = num_str.parse::<u32>() {
                                                if let Some(addr) = value.as_str() {
                                                    enclave_id_versioned.insert(num, addr.to_string());
                                                }
                                            }
                                        }
                                        if let Some(num_str) = key.strip_prefix("AutomataFmspcTcbDaoVersioned_tcbeval_") {
                                            if let Ok(num) = num_str.parse::<u32>() {
                                                if let Some(addr) = value.as_str() {
                                                    fmspc_tcb_versioned.insert(num, addr.to_string());
                                                }
                                            }
                                        }
                                    }
                                    tcb_eval_dao = obj.get("AutomataTcbEvalDao")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                }
                            }

                            let pck_dao = pccs_json["AutomataPckDao"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            let pcs_dao = pccs_json["AutomataPcsDao"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();

                            let pccs_contracts = PccsContracts {
                                pck_dao,
                                pcs_dao,
                                enclave_id_dao,
                                fmspc_tcb_dao,
                                enclave_id_versioned,
                                fmspc_tcb_versioned,
                                tcb_eval_dao,
                            };

                            // Extract DCAP contracts
                            let dcap_attestation = dcap_json["AutomataDcapAttestationFee"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            let pccs_router = dcap_json["PCCSRouter"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();

                            let dcap_contracts = DcapContracts {
                                dcap_attestation,
                                pccs_router,
                            };

                            deployments.push(DeploymentInfo {
                                chain_id,
                                network_name: metadata.name.clone(),
                                network_key: network_key.clone(),
                                testnet: metadata.testnet,
                                block_explorer: metadata.block_explorers.first()
                                    .cloned()
                                    .unwrap_or_default(),
                                pccs_contracts,
                                dcap_contracts,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort by chain_id
    deployments.sort_by_key(|d| d.chain_id);

    Ok(deployments)
}

/// Recursively copy a directory and its contents
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    // Create destination directory
    fs::create_dir_all(dst)?;

    // Iterate over source directory entries
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            // Recursively copy subdirectory
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            // Copy file
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
