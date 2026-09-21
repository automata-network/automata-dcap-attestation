//! Build the frozen production-policy fixture for the signed Alibaba V5 quote:
//! strict native verification must reject (non-zero MR_SERVICE_TD) while minimal
//! native verification must accept and produce the frozen compact journal.
//! The donor fixture contributes CA-level collateral only (CRLs, issuer chain,
//! TCB Info, QE identity, verification timestamp); the quote bytes and its PCK
//! chain are never modified. Usage:
//!   v2_alibaba_fixture DONOR_FIXTURE.json QUOTE.hex NEW_FIXTURE.json
#[path = "../tests/support/v2_fixture.rs"]
mod fixture;

use anyhow::{Context, Result, ensure};
use dcap_rs::types::collateral::Collateral;
use dcap_rs::v2::{encode_guest_input_v2, verify_guest_input_v2, verify_guest_input_v2_minimal};
use fixture::{V2Fixture, hex_bytes, sha256, unhex};
use std::io::Write;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: v2_alibaba_fixture DONOR_FIXTURE.json QUOTE.hex NEW_FIXTURE.json"
    );
    let donor: V2Fixture = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    let quote = unhex(std::fs::read_to_string(&args[1])?.trim())?;
    // Rebuild exactly like V2Fixture::rebuild_input so the donor's signed
    // collateral JSON strings stay verbatim.
    let chain = format!(
        "{}{}",
        pem::encode(&pem::Pem::new("CERTIFICATE", unhex(&donor.tcb_signing_certificate)?)),
        pem::encode(&pem::Pem::new("CERTIFICATE", unhex(&donor.root_ca_certificate)?))
    );
    let collateral = Collateral::new(
        &unhex(&donor.root_ca_crl)?,
        &unhex(&donor.pck_crl)?,
        chain.as_bytes(),
        &donor.tcb_info_json,
        &donor.qe_identity_json,
    )?;
    let input = encode_guest_input_v2(&collateral, &quote, donor.verification_timestamp)?;
    let strict = verify_guest_input_v2(&input);
    ensure!(
        strict.is_err(),
        "strict mode unexpectedly accepted the migration-service quote"
    );
    println!("strict_rejection={:?}", strict.unwrap_err());
    let journal = verify_guest_input_v2_minimal(&input)
        .context("minimal mode must accept the migration-service quote")?;
    println!(
        "minimal_acceptance: journal_bytes={} journal_sha256={}",
        journal.len(),
        sha256(&journal)
    );
    let fixture = V2Fixture {
        fixture_version: 1,
        source: concat!(
            "Signed historical Alibaba Cloud TDX 1.5 (quote v5) sample with non-zero ",
            "MR_SERVICE_TD (migration service TD). Same FMSPC as the Google v5 donor ",
            "fixture, whose CA-level collateral (CRLs, issuer chain, TCB Info, ",
            "QE identity) and verification timestamp are reused unchanged. Strict ",
            "mode rejects with the migration-service policy error; minimal mode ",
            "accepts. Never modify the quote or the signed collateral to flip this."
        )
        .to_string(),
        quote_version: 5,
        verification_timestamp: donor.verification_timestamp,
        tcb_evaluation_data_number: donor.tcb_evaluation_data_number,
        quote: hex_bytes(&quote),
        quote_sha256: sha256(&quote),
        root_ca_crl: donor.root_ca_crl.clone(),
        pck_crl: donor.pck_crl.clone(),
        tcb_signing_certificate: donor.tcb_signing_certificate.clone(),
        root_ca_certificate: donor.root_ca_certificate.clone(),
        platform_ca_certificate: donor.platform_ca_certificate.clone(),
        tcb_info_json: donor.tcb_info_json.clone(),
        qe_identity_json: donor.qe_identity_json.clone(),
        guest_input: hex_bytes(&input),
        guest_input_sha256: sha256(&input),
        expected_journal: hex_bytes(&journal),
        expected_journal_sha256: sha256(&journal),
    };
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?
        .write_all((serde_json::to_string_pretty(&fixture)? + "\n").as_bytes())?;
    println!("fixture_written={}", args[2]);
    Ok(())
}
