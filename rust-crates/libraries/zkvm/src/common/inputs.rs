use alloy_sol_types::{sol, SolType};
use anyhow::{Context, Result};
use automata_dcap_utils::Version;
use dcap_rs::types::collateral::Collateral;

/// Solidity ABI type definition for v1.1 input: (bytes collateral, bytes quote, uint64 timestamp)
type GuestInputSolType = sol!((bytes, bytes, uint64));

/// Generate version-aware zkVM input bytes from quote and collaterals
///
/// # Arguments
/// * `quote` - Raw quote bytes
/// * `collaterals` - Collaterals fetched from PCCS
/// * `timestamp` - Current timestamp (seconds since epoch)
/// * `version` - DCAP deployment version (v1.0 or v1.1)
///
/// # Returns
/// Serialized input bytes ready for zkVM proving
pub fn generate_input(
    quote: &[u8],
    collaterals: &pccs_reader_rs::Collaterals,
    timestamp: u64,
    version: Version,
) -> Result<Vec<u8>> {
    match version {
        Version::V1_0 => generate_input_v1_0(quote, collaterals, timestamp),
        Version::V1_1 => generate_input_v1_1(quote, collaterals, timestamp),
    }
}

/// Generate v1.1 input using Solidity ABI encoding
fn generate_input_v1_1(
    quote: &[u8],
    collaterals: &pccs_reader_rs::Collaterals,
    timestamp: u64,
) -> Result<Vec<u8>> {
    // Convert pccs-reader collaterals to dcap_rs Collateral
    let tcb_issuer_chain_pem = pccs_reader_rs::tcb_pem::generate_tcb_issuer_chain_pem(
        collaterals.tcb_signing_ca.as_slice(),
        collaterals.root_ca.as_slice(),
    )?;

    let collateral = Collateral::new(
        &collaterals.root_ca_crl,
        &collaterals.pck_crl,
        tcb_issuer_chain_pem.as_bytes(),
        &collaterals.tcb_info,
        &collaterals.qe_identity,
    )
    .context("Failed to create Collateral")?;

    // Solidity ABI encode: (bytes collateral, bytes quote, uint64 timestamp)
    let collateral_encoded = collateral.sol_abi_encode()?;
    let input = GuestInputSolType::abi_encode_params(&(
        collateral_encoded.as_slice(),
        quote,
        timestamp,
    ));

    Ok(input)
}

/// Generate v1.0 input using custom binary format
///
/// Format: timestamp(8 LE) + quote_len(4 LE) + collateral_len(4 LE) + quote + collateral
fn generate_input_v1_0(
    quote: &[u8],
    collaterals: &pccs_reader_rs::Collaterals,
    timestamp: u64,
) -> Result<Vec<u8>> {
    // Detect PCK type from quote to correctly serialize collaterals
    let pck_type = detect_pck_type(quote)?;

    // Serialize collaterals using v1.0 format
    let collateral_bytes = serialize_collateral_v1_0(collaterals, pck_type);

    // Build input: timestamp(8 LE) + quote_len(4 LE) + collateral_len(4 LE) + quote + collateral
    let quote_len = quote.len() as u32;
    let collateral_len = collateral_bytes.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + collateral_len;

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&timestamp.to_le_bytes());
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&collateral_len.to_le_bytes());
    input.extend_from_slice(quote);
    input.extend_from_slice(&collateral_bytes);

    Ok(input)
}

/// Serialize collaterals for v1.0 guest program
///
/// Reference: dcap-zkvm-cli/dcap-bonsai-cli/src/main.rs:322-363
fn serialize_collateral_v1_0(
    collaterals: &pccs_reader_rs::Collaterals,
    pck_type: PckType,
) -> Vec<u8> {
    // Calculate total length
    let total_length = 4 * 8  // 8 length fields (u32 each)
        + collaterals.tcb_info.len()
        + collaterals.qe_identity.len()
        + collaterals.root_ca.len()
        + collaterals.tcb_signing_ca.len()
        + collaterals.root_ca_crl.len()
        + collaterals.pck_crl.len();

    let mut data = Vec::with_capacity(total_length);

    // Write length fields (all u32 LE)
    data.extend_from_slice(&(collaterals.tcb_info.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.qe_identity.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.root_ca.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.tcb_signing_ca.len() as u32).to_le_bytes());
    data.extend_from_slice(&(0u32).to_le_bytes()); // pck_certchain_len == 0 (not used)
    data.extend_from_slice(&(collaterals.root_ca_crl.len() as u32).to_le_bytes());

    // PCK CRL ordering depends on Platform vs Processor
    match pck_type {
        PckType::Platform => {
            data.extend_from_slice(&(0u32).to_le_bytes()); // processor_crl_len = 0
            data.extend_from_slice(&(collaterals.pck_crl.len() as u32).to_le_bytes()); // platform_crl_len
        }
        PckType::Processor => {
            data.extend_from_slice(&(collaterals.pck_crl.len() as u32).to_le_bytes()); // processor_crl_len
            data.extend_from_slice(&(0u32).to_le_bytes()); // platform_crl_len = 0
        }
    }

    // Write actual data
    data.extend_from_slice(collaterals.tcb_info.as_bytes());
    data.extend_from_slice(collaterals.qe_identity.as_bytes());
    data.extend_from_slice(&collaterals.root_ca);
    data.extend_from_slice(&collaterals.tcb_signing_ca);
    data.extend_from_slice(&collaterals.root_ca_crl);
    data.extend_from_slice(&collaterals.pck_crl);

    data
}

/// Detect PCK certificate type (Platform or Processor) from quote
///
/// Reference: dcap-zkvm-cli/dcap-sp1-cli/src/parser.rs:14-44
fn detect_pck_type(quote: &[u8]) -> Result<PckType> {
    use x509_parser::prelude::*;

    // Determine quote version and TEE type
    let quote_version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);

    // Calculate QE Auth Data Size offset based on version and TEE type
    // Reference: dcap-sp1-cli/src/parser.rs:7-12
    let offset: usize = if quote_version < 4 {
        1012  // V3_SGX_QE_AUTH_DATA_SIZE_OFFSET
    } else if tee_type == 0x00000000 {  // SGX_TEE_TYPE
        1018  // V4_SGX_QE_AUTH_DATA_SIZE_OFFSET
    } else {
        1218  // V4_TDX_QE_AUTH_DATA_SIZE_OFFSET
    };

    // Get certificate data offset
    let auth_data_size = u16::from_le_bytes([quote[offset], quote[offset + 1]]);
    let cert_data_offset = offset + 2 + auth_data_size as usize + 2 + 4;

    // Parse PCK certificate from quote
    let cert_data = &quote[cert_data_offset..];
    let pem = Pem::iter_from_buffer(cert_data)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;

    if pem.is_empty() {
        anyhow::bail!("No certificates found in quote");
    }

    let cert = pem[0].parse_x509().context("Failed to parse X509 certificate")?;

    // Extract issuer CN to determine Platform vs Processor
    let issuer = cert.issuer();
    let cn = issuer
        .iter_common_name()
        .next()
        .context("No CN in issuer")?
        .as_str()
        .context("Invalid CN string")?;

    match cn {
        "Intel SGX PCK Platform CA" => Ok(PckType::Platform),
        "Intel SGX PCK Processor CA" => Ok(PckType::Processor),
        _ => anyhow::bail!("Unknown PCK issuer: {}", cn),
    }
}

/// PCK certificate type
#[derive(Debug, Clone, Copy)]
enum PckType {
    Platform,
    Processor,
}
