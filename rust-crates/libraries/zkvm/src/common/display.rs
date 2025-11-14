use anyhow::{Context, Result};
use automata_dcap_utils::Version;

use super::outputs::{parse_output, ParsedOutput};

/// Display the proof result including verified output and proof components.
///
/// This function parses and displays the journal/public values and seal/proof bytes
/// in a human-readable format. The display is consistent across all zkVM backends.
///
/// # Arguments
/// * `journal` - Journal (RISC0) or public values (SP1) bytes
/// * `proof_bytes` - Seal (RISC0) or proof (SP1) bytes
/// * `proof_label` - Label for the proof bytes (e.g., "Seal", "Proof")
/// * `version` - DCAP deployment version for parsing the output
///
/// # Returns
/// * `ParsedOutput` - The parsed output for further processing if needed
///
/// # Errors
/// Returns error if journal parsing fails
pub fn display_proof_result(
    journal: &[u8],
    proof_bytes: &[u8],
    proof_label: &str,
    version: Version,
) -> Result<ParsedOutput> {
    let parsed_output = parse_output(journal, version).context("Failed to parse output journal")?;

    println!("\n=== Proof Generation Complete ===");
    println!(
        "Verified Output {}: {}",
        version.to_string(),
        parsed_output.verified_output
    );
    println!("Timestamp: {}", parsed_output.current_time);
    println!(
        "TCB Info Root Hash: {}",
        hex::encode(&parsed_output.tcbinfo_root_hash)
    );
    println!(
        "Enclave Identity Root Hash: {}",
        hex::encode(&parsed_output.enclaveidentity_root_hash)
    );
    println!(
        "Root Cert Hash: {}",
        hex::encode(&parsed_output.root_cert_hash)
    );
    println!(
        "Signing Cert Hash: {}",
        hex::encode(&parsed_output.signing_cert_hash)
    );
    println!(
        "Root CRL Hash: {}",
        hex::encode(&parsed_output.root_crl_hash)
    );
    println!("PCK CRL Hash: {}", hex::encode(&parsed_output.pck_crl_hash));

    println!("\nJournal: {}", hex::encode(journal));
    println!("{}: {}", proof_label, hex::encode(proof_bytes));

    Ok(parsed_output)
}
