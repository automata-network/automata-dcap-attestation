use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{bail, Context, Result};
use automata_dcap_network_registry::Network;
use automata_dcap_qpl::{
    detect_missing_collateral, sgx_ql_get_quote_config, sgx_ql_get_quote_verification_collateral,
    sgx_ql_get_qve_identity, sgx_ql_get_root_ca_crl, tdx_ql_get_quote_verification_collateral,
    CollateralError, DataSource, MissingCollateral, MissingCollateralReport, SgxCpuSvn, SgxIsvSvn,
    SgxQlPckCertId,
};
use automata_dcap_utils::{
    parser::{parse_output, parse_quote},
    quote, Version,
};
use automata_dcap_verifier::{
    utils::read_proof_artifact, verify_and_attest_on_chain, verify_and_attest_with_zk_proof,
    ZkCoprocessor,
};
#[cfg(feature = "pico")]
use automata_dcap_zkvm::{run_pico_command, PicoCommand};
#[cfg(feature = "risc0")]
use automata_dcap_zkvm::{run_risc0_command, Risc0Command};
#[cfg(feature = "sp1")]
use automata_dcap_zkvm::{run_sp1_command, Sp1Command};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::task;

/// zkVM types for CLI argument parsing
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ZkvmType {
    /// RISC0 zkVM
    Risc0,
    /// SP1 zkVM
    Sp1,
    /// Pico zkVM
    Pico,
}

impl From<ZkvmType> for ZkCoprocessor {
    fn from(zkvm: ZkvmType) -> Self {
        match zkvm {
            ZkvmType::Risc0 => ZkCoprocessor::Risc0,
            ZkvmType::Sp1 => ZkCoprocessor::Sp1,
            ZkvmType::Pico => ZkCoprocessor::Pico,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "automata-dcap",
    author,
    version,
    about = "Command-line tool for Automata DCAP attestation workflows"
)]
struct Cli {
    /// Network to use (e.g., automata_testnet, arbitrum_mainnet, eth_mainnet)
    #[arg(long, env = "AUTOMATA_DCAP_NETWORK", global = true)]
    network: Option<String>,

    /// Override RPC URL (takes precedence over network's default RPC)
    #[arg(long, env = "AUTOMATA_DCAP_RPC_URL", global = true)]
    rpc_url: Option<String>,

    /// Private key for signing transactions
    #[arg(
        long,
        env = "AUTOMATA_DCAP_PRIVATE_KEY",
        global = true,
        hide_env_values = true
    )]
    private_key: Option<String>,

    /// Path to quote file (can be binary or hex string)
    #[arg(long, global = true, conflicts_with = "quote_hex")]
    quote_path: Option<String>,

    /// Quote provided as hex string
    #[arg(long, global = true, conflicts_with = "quote_path")]
    quote_hex: Option<String>,

    /// Optional TCB evaluation data number to use for collateral resolution.
    ///
    /// Uses `standard()` TCB evaluation data number if not provided
    #[arg(long, global = true)]
    tcb_eval_number: Option<u32>,

    /// DCAP deployment version to use (v1.0 or v1.1). Defaults to v1.1 if not specified.
    #[arg(
        long,
        env = "AUTOMATA_DCAP_VERSION",
        global = true,
        value_name = "DCAP_DEPLOYMENT_VERSION"
    )]
    dcap_version: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage and monitor collaterals on-chain
    Qpl {
        #[command(subcommand)]
        command: QplCommands,
    },

    /// Generate zkVM proofs and utilities for supported zkVMs
    #[command(subcommand)]
    Zkvm(ZkvmCommands),

    /// Verify quotes on-chain or with ZK proofs
    Verify {
        #[command(subcommand)]
        command: VerifyCommands,
    },

    /// List supported networks
    Networks {
        /// Filter networks by type
        #[arg(long, value_enum)]
        filter: Option<NetworkFilter>,
    },

    /// Inspect quote and/or verified output structures
    Inspect {
        /// Path to output file (can be binary or hex string)
        #[arg(long, conflicts_with = "output_hex")]
        output_path: Option<String>,

        /// Output provided as hex string
        #[arg(long, conflicts_with = "output_path")]
        output_hex: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum VerifyCommands {
    /// Verify quote on-chain using smart contract
    Onchain,

    /// Verify quote with ZK proof
    Zk {
        /// Path to zkVM proof artifact JSON file
        #[arg(long, conflicts_with_all = ["zkvm", "journal", "proof"])]
        artifact: Option<String>,

        /// zkVM type (required if not using --artifact)
        #[arg(long, value_enum, requires = "journal", requires = "proof")]
        zkvm: Option<ZkvmType>,

        /// Journal/output bytes as hex string or file path (required if not using --artifact)
        #[arg(long)]
        journal: Option<String>,

        /// Proof bytes as hex string or file path (required if not using --artifact)
        #[arg(long)]
        proof: Option<String>,

        /// Program identifier as hex string (optional)
        #[arg(long)]
        program_id: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum StatusFilter {
    Mainnet,
    Testnet,
    All,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SourceArg {
    Azure,
    Local,
    All,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum NetworkFilter {
    Mainnet,
    Testnet,
    All,
}

impl From<SourceArg> for DataSource {
    fn from(value: SourceArg) -> Self {
        match value {
            SourceArg::Azure => DataSource::Azure,
            SourceArg::Local => DataSource::Local,
            SourceArg::All => DataSource::All,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PckCaArg {
    Platform,
    Processor,
}

impl PckCaArg {
    fn as_str(self) -> &'static str {
        match self {
            PckCaArg::Platform => "platform",
            PckCaArg::Processor => "processor",
        }
    }
}

#[derive(Args, Debug, Clone)]
struct QuoteConfigArgs {
    #[arg(long, value_enum, default_value_t = SourceArg::All)]
    source: SourceArg,
    #[arg(
        long = "collateral-version",
        default_value = "v3",
        alias = "collateral_version"
    )]
    collateral_version: String,
    #[arg(
        long = "pccs-url",
        default_value = "https://api.trustedservices.intel.com",
        alias = "pccs_url"
    )]
    pccs_url: String,
    #[arg(long = "qe-id", alias = "qe_id")]
    qe_id: String,
    #[arg(long = "platform-cpu-svn", alias = "platform_cpu_svn")]
    platform_cpu_svn: String,
    #[arg(long = "platform-pce-isv-svn", alias = "platform_pce_isv_svn")]
    platform_pce_isv_svn: String,
    #[arg(long = "encrypted-ppid", alias = "encrypted_ppid")]
    encrypted_ppid: String,
    #[arg(long = "pce-id", alias = "pce_id")]
    pce_id: String,
}

#[derive(Args, Debug, Clone)]
struct QuoteCollateralArgs {
    #[arg(long, value_enum, default_value_t = SourceArg::All)]
    source: SourceArg,
    #[arg(
        long = "collateral-version",
        default_value = "v3",
        alias = "collateral_version"
    )]
    collateral_version: String,
    #[arg(
        long = "pccs-url",
        default_value = "https://api.trustedservices.intel.com",
        alias = "pccs_url"
    )]
    pccs_url: String,
    #[arg(long)]
    fmspc: String,
    #[arg(long = "pck-ca", value_enum, default_value_t = PckCaArg::Platform, alias = "pck_ca")]
    pck_ca: PckCaArg,
    #[arg(
        long = "all-verification-collateral",
        default_value_t = 0,
        alias = "all_verification_collateral"
    )]
    all_verification_collateral: u64,
}

#[derive(Args, Debug, Clone)]
struct CollateralBasicArgs {
    #[arg(long, value_enum, default_value_t = SourceArg::All)]
    source: SourceArg,
    #[arg(
        long = "collateral-version",
        default_value = "v3",
        alias = "collateral_version"
    )]
    collateral_version: String,
    #[arg(
        long = "pccs-url",
        default_value = "https://api.trustedservices.intel.com",
        alias = "pccs_url"
    )]
    pccs_url: String,
}

#[derive(Subcommand, Debug)]
enum QplCommands {
    /// Check PCCS collateral status across networks (no quote required)
    Status {
        /// Filter networks by type
        #[arg(long, value_enum, default_value = "all")]
        filter: StatusFilter,
    },
    /// Inspect which collaterals are missing for a quote
    Check {
        /// Check across all networks (mainnet, testnet, or both)
        #[arg(long, value_enum)]
        all_networks: Option<NetworkFilter>,
    },
    /// Call a specific QPL function
    Function {
        #[command(subcommand)]
        function: QplFunction,
    },
}

#[derive(Subcommand, Debug)]
enum QplFunction {
    /// Call sgx_ql_get_quote_config
    #[command(name = "sgx_ql_get_quote_config")]
    SgxQlGetQuoteConfig(QuoteConfigArgs),
    /// Call sgx_ql_get_quote_verification_collateral for SGX
    #[command(name = "sgx_ql_get_quote_verification_collateral")]
    SgxQlGetQuoteVerificationCollateral(QuoteCollateralArgs),
    /// Call tdx_ql_get_quote_verification_collateral for TDX
    #[command(name = "tdx_ql_get_quote_verification_collateral")]
    TdxQlGetQuoteVerificationCollateral(QuoteCollateralArgs),
    /// Call sgx_ql_get_qve_identity
    #[command(name = "sgx_ql_get_qve_identity")]
    SgxQlGetQveIdentity(CollateralBasicArgs),
    /// Call sgx_ql_get_root_ca_crl
    #[command(name = "sgx_ql_get_root_ca_crl")]
    SgxQlGetRootCaCrl(CollateralBasicArgs),
}

#[derive(Subcommand, Debug)]
enum ZkvmCommands {
    /// RISC Zero zkVM tooling (proof generation, deserialization, etc.)
    #[cfg(feature = "risc0")]
    #[command(subcommand)]
    Risc0(Risc0Command),

    /// SP1 zkVM tooling (proof generation, deserialization, etc.)
    #[cfg(feature = "sp1")]
    #[command(subcommand)]
    Sp1(Sp1Command),

    /// Pico zkVM tooling (proof generation, deserialization, etc.)
    #[cfg(feature = "pico")]
    #[command(subcommand)]
    Pico(PicoCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger at the very beginning
    let _ = env_logger::try_init();

    // Load environment variables from .env file if present
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Resolve deployment version (defaults to v1.1 if not specified)
    let dcap_version = if let Some(version_str) = cli.dcap_version.as_deref() {
        version_str.parse::<Version>()?
    } else {
        Version::V1_1 // Default to v1.1
    };

    println!("Using DCAP deployment version: {}", dcap_version);

    // Create provider with smart network resolution and validation
    let provider = get_provider_from_network_params(&cli, dcap_version).await?;

    // Extract network from provider with the specified deployment version
    let network = if let Some(network) = &cli.network {
        Network::by_key(network, Some(dcap_version)).context(format!(
            "Network '{}' not found for DCAP version {}",
            network, dcap_version
        ))?
    } else {
        Network::from_provider(&provider, Some(dcap_version)).await?
    };

    // Parse quote from global arguments if provided
    let quote_bytes = match (&cli.quote_path, &cli.quote_hex) {
        (Some(path), None) => Some(quote::read_from_path(path)?),
        (None, Some(hex)) => Some(quote::parse_hex(hex)?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            bail!("Cannot provide both --quote-path and --quote-hex");
        }
    };

    match cli.command {
        Commands::Qpl { command } => match command {
            QplCommands::Status { filter } => {
                let network_filter = match filter {
                    StatusFilter::Mainnet => NetworkFilter::Mainnet,
                    StatusFilter::Testnet => NetworkFilter::Testnet,
                    StatusFilter::All => NetworkFilter::All,
                };
                handle_collateral_status(network_filter, dcap_version).await?
            }
            QplCommands::Check { all_networks } => {
                if let Some(filter) = all_networks {
                    handle_quote_all_networks(
                        filter,
                        quote_bytes.as_ref(),
                        cli.tcb_eval_number,
                        dcap_version,
                    )
                    .await?
                } else {
                    handle_quote(network, quote_bytes.as_ref(), cli.tcb_eval_number).await?
                }
            }
            QplCommands::Function { function } => {
                // Validate that private_key was provided for QPL write operations
                cli.private_key
                    .as_ref()
                    .context("--private-key is required for QPL call commands")?;

                match function {
                    QplFunction::SgxQlGetQuoteConfig(args) => {
                        handle_quote_config(provider, args).await?
                    }
                    QplFunction::SgxQlGetQuoteVerificationCollateral(args) => {
                        handle_quote_collateral(provider, args).await?
                    }
                    QplFunction::TdxQlGetQuoteVerificationCollateral(args) => {
                        handle_tdx_collateral(provider, args).await?
                    }
                    QplFunction::SgxQlGetQveIdentity(args) => {
                        handle_qve_identity(provider, args).await?
                    }
                    QplFunction::SgxQlGetRootCaCrl(args) => {
                        handle_root_ca_crl(provider, args).await?
                    }
                }
            }
        },
        Commands::Zkvm(zkvm_cmd) => {
            // Pass provider directly to zkVM commands
            // Provider is used to fetch collaterals from on-chain PCCS DAOs
            match zkvm_cmd {
                #[cfg(feature = "risc0")]
                ZkvmCommands::Risc0(command) => {
                    run_risc0_command(
                        command,
                        quote_bytes,
                        &provider,
                        dcap_version,
                        cli.tcb_eval_number,
                    )
                    .await?
                }
                #[cfg(feature = "sp1")]
                ZkvmCommands::Sp1(command) => {
                    run_sp1_command(
                        command,
                        quote_bytes,
                        &provider,
                        dcap_version,
                        cli.tcb_eval_number,
                    )
                    .await?
                }
                #[cfg(feature = "pico")]
                ZkvmCommands::Pico(command) => {
                    run_pico_command(
                        command,
                        quote_bytes,
                        &provider,
                        dcap_version,
                        cli.tcb_eval_number,
                    )
                    .await?
                }
            }
        }
        Commands::Verify { command } => match command {
            VerifyCommands::Onchain => {
                // Onchain verification requires a quote
                let quote_bytes = quote_bytes.context(
                    "Quote is required for onchain verification. Please provide --quote-path or --quote-hex",
                )?;

                println!("Verifying quote on-chain...");

                let verified_output_bytes = verify_and_attest_on_chain(
                    &provider,
                    Some(dcap_version),
                    &quote_bytes,
                    cli.tcb_eval_number,
                )
                .await?;

                print_verified_output(&verified_output_bytes, dcap_version)?;
            }
            VerifyCommands::Zk {
                artifact,
                zkvm,
                journal,
                proof,
                program_id,
            } => {
                if let Some(artifact_path) = artifact {
                    // Path 1: Use artifact file
                    println!("Reading proof artifact from: {}", artifact_path);
                    let parsed = read_proof_artifact(&artifact_path)?;

                    println!("Verifying ZK proof on-chain...");
                    println!("  zkVM: {:?}", parsed.zk_coprocessor);
                    println!("  Program ID: {}", hex::encode(&parsed.program_identifier));

                    let verified_output_bytes = verify_and_attest_with_zk_proof(
                        &provider,
                        Some(dcap_version),
                        &parsed.output_bytes,
                        parsed.zk_coprocessor,
                        &parsed.proof_bytes,
                        Some(parsed.program_identifier),
                        cli.tcb_eval_number,
                    )
                    .await?;

                    print_verified_output(&verified_output_bytes, dcap_version)?;
                } else {
                    // Path 2: Use manual arguments
                    let zkvm = zkvm.context("--zkvm is required when not using --artifact")?;
                    let journal =
                        journal.context("--journal is required when not using --artifact")?;
                    let proof = proof.context("--proof is required when not using --artifact")?;

                    // Decode journal (support both hex and file path)
                    let output_bytes = if let Ok(bytes) = hex::decode(&journal) {
                        bytes
                    } else {
                        quote::read_from_path(&journal)?
                    };

                    // Decode proof (support both hex and file path)
                    let proof_bytes = if let Ok(bytes) = hex::decode(&proof) {
                        bytes
                    } else {
                        quote::read_from_path(&proof)?
                    };

                    // Decode program_id if provided
                    let program_identifier = if let Some(pid) = program_id {
                        let pid_bytes =
                            hex::decode(&pid).context("Failed to decode program_id as hex")?;
                        if pid_bytes.len() != 32 {
                            bail!(
                                "program_id must be 32 bytes (64 hex chars), got {}",
                                pid_bytes.len()
                            );
                        }
                        Some(alloy::primitives::FixedBytes::<32>::from_slice(&pid_bytes))
                    } else {
                        None
                    };

                    println!("Verifying ZK proof on-chain...");
                    println!("  zkVM: {:?}", zkvm);

                    let verified_output_bytes = verify_and_attest_with_zk_proof(
                        &provider,
                        Some(dcap_version),
                        &output_bytes,
                        zkvm.into(),
                        &proof_bytes,
                        program_identifier,
                        cli.tcb_eval_number,
                    )
                    .await?;

                    print_verified_output(&verified_output_bytes, dcap_version)?;
                }
            }
        },
        Commands::Networks { filter } => {
            handle_list_networks(filter, dcap_version);
        }
        Commands::Inspect {
            output_path,
            output_hex,
        } => {
            handle_inspect(
                quote_bytes.as_ref(),
                output_path.as_deref(),
                output_hex.as_deref(),
                dcap_version,
            )?;
        }
    }

    Ok(())
}

fn print_verified_output(verified_output_bytes: &[u8], dcap_version: Version) -> Result<()> {
    let verified_output = parse_output(&verified_output_bytes, dcap_version)?;

    println!("\n✓ Verification successful!");
    println!("=== Verified Output ===");
    println!("{}", verified_output);

    Ok(())
}

async fn handle_collateral_status(filter: NetworkFilter, version: Version) -> Result<()> {
    use pccs_reader_rs::pccs::pcs::{get_certificate_by_id, CA};

    let networks: Vec<&Network> = Network::all(Some(version))
        .iter()
        .filter(|net| match filter {
            NetworkFilter::Mainnet => !net.testnet,
            NetworkFilter::Testnet => net.testnet,
            NetworkFilter::All => true,
        })
        .collect();

    println!("PCCS Collateral Status Report");
    println!(
        "Checking {} networks...",
        networks.len()
    );
    println!("{}\n", "=".repeat(80));

    for network in networks {
        println!(
            "Network: {} ({}, chain_id: {})",
            network.display_name, network.key, network.chain_id
        );
        println!("RPC: {}", network.default_rpc_url());
        println!();

        // Create provider for this network (read-only, no private key needed)
        let network_provider = match network.create_provider(None, None) {
            Ok(p) => p,
            Err(e) => {
                println!("  [ERR] Failed to create provider: {}", e);
                continue;
            }
        };

        // Check PCS Certificates & CRLs
        println!("  PCS Certificates:");
        for (ca, name) in [
            (CA::Root, "Root CA"),
            (CA::Signing, "Signing CA"),
            (CA::Processor, "Processor CA"),
            (CA::Platform, "Platform CA"),
        ] {
            match get_certificate_by_id(&network_provider, Some(version), ca).await {
                Ok((cert, crl)) => {
                    let cert_status = if cert.is_empty() {
                        "MISSING"
                    } else {
                        "present"
                    };
                    let crl_status = if crl.is_empty() { "MISSING" } else { "present" };

                    if cert.is_empty() || crl.is_empty() {
                        println!(
                            "    [!!] {} - cert: {}, CRL: {}",
                            name, cert_status, crl_status
                        );
                    } else {
                        println!(
                            "    [OK] {} - cert: {}, CRL: {}",
                            name, cert_status, crl_status
                        );
                    }
                }
                Err(e) => println!("    [ERR] {} - Error: {}", name, e),
            }
        }

        println!("\n{}\n", "-".repeat(80));
    }

    Ok(())
}

/// Creates a provider from CLI arguments with smart network resolution and validation
async fn get_provider_from_network_params(cli: &Cli, version: Version) -> Result<impl Provider> {
    use Network;

    match (&cli.network, &cli.rpc_url) {
        // Case A: Both --network and --rpc-url provided - validate chain_id
        (Some(network_key), Some(custom_rpc)) => {
            let network = Network::by_key(network_key, Some(version))
                .with_context(|| format!("unknown network key: {}", network_key))?;

            let provider = network.create_provider(Some(custom_rpc), cli.private_key.as_deref())?;

            // Validate chain_id matches
            let queried_chain_id = provider.get_chain_id().await?;
            if queried_chain_id != network.chain_id {
                bail!(
                    "RPC chain_id {} doesn't match network '{}' (expected chain_id {})",
                    queried_chain_id,
                    network.display_name,
                    network.chain_id
                );
            }
            log::info!(
                "Using network: {} with custom RPC (validated chain_id: {})",
                network.display_name,
                queried_chain_id
            );

            Ok(provider)
        }

        // Case B: Only --rpc-url provided - auto-detect network
        (None, Some(custom_rpc)) => {
            // Create temporary provider to detect network chain_id
            let temp_provider = ProviderBuilder::new().connect_http(custom_rpc.parse()?);
            let chain_id = temp_provider.get_chain_id().await?;

            // Validate it's a supported network
            let network = Network::by_chain_id(chain_id, Some(version))
                .with_context(|| format!("Unsupported chain_id: {}", chain_id))?;

            // Create actual provider using network's method for consistent type
            let provider = network.create_provider(Some(custom_rpc), cli.private_key.as_deref())?;

            log::info!(
                "Auto-detected network: {} (chain_id: {})",
                network.display_name,
                network.chain_id
            );

            Ok(provider)
        }

        // Case C: Only --network provided
        (Some(network_key), None) => {
            let network = Network::by_key(network_key, Some(version))
                .with_context(|| format!("unknown network key: {}", network_key))?;

            let provider = network.create_provider(None, cli.private_key.as_deref())?;

            log::info!(
                "Using network: {} (chain_id: {})",
                network.display_name,
                network.chain_id
            );

            Ok(provider)
        }

        // Case D: Neither provided - use default network
        (None, None) => {
            let network =
                Network::default_network(Some(version)).expect("Default network should exist");

            let provider = network.create_provider(None, cli.private_key.as_deref())?;

            log::info!(
                "Using default network: {} (chain_id: {})",
                network.display_name,
                network.chain_id
            );

            Ok(provider)
        }
    }
}

fn handle_list_networks(filter: Option<NetworkFilter>, version: Version) {
    let networks: Vec<&Network> = Network::all(Some(version))
        .iter()
        .filter(|net| match filter {
            Some(NetworkFilter::Mainnet) => !net.testnet,
            Some(NetworkFilter::Testnet) => net.testnet,
            Some(NetworkFilter::All) | None => true,
        })
        .collect();

    let filter_name = match filter {
        Some(NetworkFilter::Mainnet) => "Mainnet",
        Some(NetworkFilter::Testnet) => "Testnet",
        Some(NetworkFilter::All) | None => "All",
    };

    println!(
        "Supported Networks ({} - {} networks - version {})",
        filter_name,
        networks.len(),
        version
    );
    println!("{}", "=".repeat(80));

    for network in networks {
        println!("\n  {} ({})", network.display_name, network.key);
        println!("    Chain ID:    {}", network.chain_id);
        println!("    Default RPC: {}", network.default_rpc_url());
        if network.rpc_endpoints.len() > 1 {
            println!("    Backup RPCs: {}", network.rpc_endpoints.len() - 1);
        }
        if let Some(gas_price) = network.gas_price_hint_wei {
            println!("    Gas hint:    {} wei", gas_price);
        }
    }
}

fn handle_inspect(
    quote_bytes: Option<&Vec<u8>>,
    output_path: Option<&str>,
    output_hex: Option<&str>,
    version: Version,
) -> Result<()> {
    let mut something_inspected = false;

    // Inspect quote if provided
    if let Some(bytes) = quote_bytes {
        println!("=== Quote Inspection ===\n");
        let quote = parse_quote(bytes).context("Failed to parse quote bytes")?;
        println!("{}", quote);
        something_inspected = true;
    }

    // Inspect output if provided
    if output_path.is_some() || output_hex.is_some() {
        if something_inspected {
            println!("\n");
        }
        println!("=== Verified Output Inspection ===\n");

        let output_bytes = match (output_path, output_hex) {
            (Some(path), None) => {
                quote::read_from_path(path).context("Failed to read output from path")?
            }
            (None, Some(hex)) => quote::parse_hex(hex).context("Failed to parse output hex")?,
            _ => bail!("Internal error: should not have both output_path and output_hex"),
        };

        print_verified_output(output_bytes.as_slice(), version)?;
        something_inspected = true;
    }

    if !something_inspected {
        bail!("No data to inspect. Please provide --quote-path/--quote-hex and/or --output-path/--output-hex");
    }

    Ok(())
}

async fn handle_quote_config<P: Provider + Send + Sync + 'static>(
    provider: P,
    args: QuoteConfigArgs,
) -> Result<()> {
    let join = task::spawn_blocking(move || -> Result<()> {
        let mut qe_id = decode_hex_exact(&args.qe_id, 16, "qe-id")?;
        let cpu_bytes = decode_hex_exact(&args.platform_cpu_svn, 16, "platform-cpu-svn")?;
        let mut cpu_svn = Box::new(SgxCpuSvn { cpu_svn: [0; 16] });
        cpu_svn.cpu_svn.copy_from_slice(&cpu_bytes);

        let isv_bytes = decode_hex_exact(&args.platform_pce_isv_svn, 2, "platform-pce-isv-svn")?;
        let mut isv_svn = Box::new(SgxIsvSvn {
            isv_svn: u16::from_le_bytes([isv_bytes[0], isv_bytes[1]]),
        });

        let mut encrypted_ppid = decode_hex_exact(&args.encrypted_ppid, 384, "encrypted-ppid")?;
        let pce_bytes = decode_hex_exact(&args.pce_id, 2, "pce-id")?;
        let pce_id = u16::from_le_bytes([pce_bytes[0], pce_bytes[1]]);

        let data_source: DataSource = args.source.into();

        let pck_cert_id = SgxQlPckCertId {
            p_qe3_id: qe_id.as_mut_ptr(),
            qe3_id_size: qe_id.len() as u32,
            p_platform_cpu_svn: cpu_svn.as_mut() as *mut SgxCpuSvn,
            p_platform_pce_isv_svn: isv_svn.as_mut() as *mut SgxIsvSvn,
            p_encrypted_ppid: encrypted_ppid.as_mut_ptr(),
            encrypted_ppid_size: encrypted_ppid.len() as u32,
            crypto_suite: 1,
            pce_id,
        };

        sgx_ql_get_quote_config(
            &provider,
            None,
            pck_cert_id,
            data_source,
            args.collateral_version,
            args.pccs_url,
        );

        Ok(())
    })
    .await
    .context("quote-config task join failed")?;
    join?;
    Ok(())
}

async fn handle_quote_collateral<P: Provider + Send + Sync + 'static>(
    provider: P,
    args: QuoteCollateralArgs,
) -> Result<()> {
    let join = task::spawn_blocking(move || -> Result<()> {
        let data_source: DataSource = args.source.into();
        let fmspc = args.fmspc.trim_start_matches("0x").to_string();
        let pck_ca = args.pck_ca.as_str().to_string();

        sgx_ql_get_quote_verification_collateral(
            &provider,
            None,
            fmspc,
            pck_ca,
            data_source,
            args.collateral_version,
            args.pccs_url,
            args.all_verification_collateral,
        );

        Ok(())
    })
    .await
    .context("sgx quote-collateral task join failed")?;
    join?;
    Ok(())
}

async fn handle_tdx_collateral<P: Provider + Send + Sync + 'static>(
    provider: P,
    args: QuoteCollateralArgs,
) -> Result<()> {
    let join = task::spawn_blocking(move || -> Result<()> {
        let data_source: DataSource = args.source.into();
        let fmspc = args.fmspc.trim_start_matches("0x").to_string();
        let pck_ca = args.pck_ca.as_str().to_string();

        tdx_ql_get_quote_verification_collateral(
            &provider,
            None,
            fmspc,
            pck_ca,
            data_source,
            args.collateral_version,
            args.pccs_url,
            args.all_verification_collateral,
        );

        Ok(())
    })
    .await
    .context("tdx quote-collateral task join failed")?;
    join?;
    Ok(())
}

async fn handle_qve_identity<P: Provider + Send + Sync + 'static>(
    provider: P,
    args: CollateralBasicArgs,
) -> Result<()> {
    let join = task::spawn_blocking(move || -> Result<()> {
        let data_source: DataSource = args.source.into();
        sgx_ql_get_qve_identity(
            &provider,
            None,
            data_source,
            args.collateral_version,
            args.pccs_url,
        );
        Ok(())
    })
    .await
    .context("qve-identity task join failed")?;
    join?;
    Ok(())
}

async fn handle_root_ca_crl<P: Provider + Send + Sync + 'static>(
    provider: P,
    args: CollateralBasicArgs,
) -> Result<()> {
    let join = task::spawn_blocking(move || -> Result<()> {
        let data_source: DataSource = args.source.into();
        sgx_ql_get_root_ca_crl(
            &provider,
            None,
            data_source,
            args.collateral_version,
            args.pccs_url,
        );
        Ok(())
    })
    .await
    .context("root-ca-crl task join failed")?;
    join?;
    Ok(())
}

async fn handle_quote_all_networks(
    filter: NetworkFilter,
    quote_bytes: Option<&Vec<u8>>,
    tcb_eval_number: Option<u32>,
    version: Version,
) -> Result<()> {
    let quote_bytes = match quote_bytes {
        Some(bytes) => bytes.clone(),
        None => {
            println!("no quote provided; pass --quote-path or --quote-hex");
            return Ok(());
        }
    };

    let networks: Vec<&'static Network> = Network::all(Some(version))
        .iter()
        .filter(|net| match filter {
            NetworkFilter::Mainnet => !net.testnet,
            NetworkFilter::Testnet => net.testnet,
            NetworkFilter::All => true,
        })
        .collect();

    println!("Checking collaterals across {} networks...", networks.len());
    println!("{}", "=".repeat(80));

    // Check all networks in parallel
    let mut handles = vec![];
    for network in networks {
        let quote_clone = quote_bytes.clone();
        let key = network.key.clone();
        let display_name = network.display_name.clone();
        let chain_id = network.chain_id;
        let handle = tokio::spawn(async move {
            let result = detect_missing_collateral(network, &quote_clone, tcb_eval_number).await;
            (key, display_name, chain_id, result)
        });
        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await?);
    }

    // Sort by network key for consistent output
    results.sort_by_key(|(key, _, _, _)| key.clone());

    // Categorize results
    let mut ok_networks = vec![];
    let mut missing_networks = vec![];
    let mut error_networks = vec![];

    for (key, display_name, chain_id, result) in results {
        match result {
            Ok(()) => {
                ok_networks.push((key, display_name, chain_id));
            }
            Err(CollateralError::Missing(report)) => {
                missing_networks.push((key, display_name, chain_id, report));
            }
            Err(e) => {
                error_networks.push((key, display_name, chain_id, format!("{}", e)));
            }
        }
    }

    // Print summary
    println!("\nSUMMARY:");
    println!(
        "  Up-to-date: {}/{}",
        ok_networks.len(),
        ok_networks.len() + missing_networks.len() + error_networks.len()
    );
    println!("  Issues:     {}", missing_networks.len());
    println!("  Errors:     {}", error_networks.len());
    println!("{}", "=".repeat(80));

    // Print up-to-date networks
    if !ok_networks.is_empty() {
        println!("\nUP-TO-DATE NETWORKS ({}):", ok_networks.len());
        for (key, display_name, chain_id) in ok_networks {
            println!("  [OK] {} (chain_id: {})", display_name, chain_id);
            println!("       key: {}", key);
        }
    }

    // Print networks with issues
    if !missing_networks.is_empty() {
        println!(
            "\nNETWORKS WITH MISSING/OUTDATED COLLATERALS ({}):",
            missing_networks.len()
        );
        for (key, display_name, chain_id, report) in missing_networks {
            println!("\n  [!!] {} (chain_id: {})", display_name, chain_id);
            println!("       key: {}", key);
            println!("       issues ({}):", report.len());
            for (idx, missing) in report.iter().enumerate() {
                print!("         {}. ", idx + 1);
                match missing {
                    MissingCollateral::QEIdentity(kind, version) => {
                        println!("Missing QE identity (kind={:?}, version={})", kind, version)
                    }
                    MissingCollateral::FMSPCTCB(kind, fmspc, version) => {
                        println!(
                            "Missing FMSPC/TCB (tcb_type={}, fmspc={}, version={})",
                            kind, fmspc, version
                        )
                    }
                    MissingCollateral::PCS(ca, missing_cert, missing_crl) => {
                        println!(
                            "Missing PCS for {:?} (cert={}, crl={})",
                            ca, missing_cert, missing_crl
                        )
                    }
                }
            }
        }
    }

    // Print errors
    if !error_networks.is_empty() {
        println!("\nNETWORKS WITH ERRORS ({}):", error_networks.len());
        for (key, display_name, chain_id, error) in error_networks {
            println!("\n  [ERR] {} (chain_id: {})", display_name, chain_id);
            println!("        key: {}", key);
            println!("        error: {}", error);
        }
    }

    println!("\n{}", "=".repeat(80));

    Ok(())
}

async fn handle_quote(
    network: &'static Network,
    quote_bytes: Option<&Vec<u8>>,
    tcb_eval_number: Option<u32>,
) -> Result<()> {
    let quote_bytes = match quote_bytes {
        Some(bytes) => bytes,
        None => {
            println!("no quote provided; pass --quote-path or --quote-hex");
            return Ok(());
        }
    };

    match detect_missing_collateral(network, quote_bytes, tcb_eval_number).await {
        Ok(()) => {
            println!("All required collaterals are present.");
        }
        Err(CollateralError::Missing(report)) => {
            print_missing_collateral_report(report);
        }
        Err(CollateralError::Validation(msg)) => {
            bail!("Validation error: {}", msg);
        }
    }

    Ok(())
}

fn decode_hex_exact(input: &str, expected_len: usize, label: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(input)?;
    if bytes.len() != expected_len {
        bail!(
            "{} must be {} bytes (got {})",
            label,
            expected_len,
            bytes.len()
        );
    }
    Ok(bytes)
}

fn print_missing_collateral_report(report: MissingCollateralReport) {
    println!("Found {} missing collateral(s):", report.len());
    for (idx, missing) in report.iter().enumerate() {
        print!("  {}. ", idx + 1);
        match missing {
            MissingCollateral::QEIdentity(kind, version) => {
                println!(
                    "Missing QE identity collateral: kind={:?}, version={}",
                    kind, version
                );
            }
            MissingCollateral::FMSPCTCB(kind, fmspc, version) => {
                println!(
                    "Missing FMSPC/TCB collateral: tcb_type={}, fmspc={}, version={}",
                    kind, fmspc, version
                );
            }
            MissingCollateral::PCS(ca, missing_cert, missing_crl) => {
                println!(
                    "Missing PCS collateral for {:?}: cert_missing={}, crl_missing={}",
                    ca, missing_cert, missing_crl
                );
            }
        }
    }
}
