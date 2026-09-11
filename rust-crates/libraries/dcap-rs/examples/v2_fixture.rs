//! Capture a public diagnostic ABI input, or reconstruct one entirely offline.
//! Capture is an explicit maintenance command; tests never regenerate expectations.
#[path = "../tests/support/v2_fixture.rs"]
mod fixture;

use std::io::Write;

use alloy_sol_types::SolType;
use anyhow::{Context, Result, ensure};
use dcap_rs::types::VerifiedOutputV2;
use dcap_rs::types::collateral::CollateralSol;
use dcap_rs::types::quote::Quote;
use dcap_rs::v2::verify_guest_input_v2;
use fixture::{GuestInput, V2Fixture, hex_bytes, sha256, unhex};
use x509_cert::der::Encode;

fn write_new(path: &str, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() >= 3,
        "usage: v2_fixture capture INPUT OUTPUT.json SOURCE | export FIXTURE.json OUTPUT.bin"
    );
    ensure!(
        !std::path::Path::new(&args[2]).exists(),
        "output exists; refusing to overwrite"
    );
    match args[0].as_str() {
        "capture" => {
            ensure!(args.len() == 4, "capture requires a provenance description");
            let input = std::fs::read(&args[1])?;
            let journal = verify_guest_input_v2(&input)?;
            let output = VerifiedOutputV2::from_bytes(&journal)?;
            let (collateral, quote, timestamp) = GuestInput::abi_decode_params(&input)?;
            let (root_crl, pck_crl, chain, tcb, qe) =
                CollateralSol::abi_decode_params(&collateral)?;
            let mut raw = quote.as_ref();
            let parsed = Quote::read(&mut raw)?;
            let pck_chain = parsed.signature.get_pck_cert_chain()?;
            let platform_ca = pck_chain
                .pck_cert_chain
                .get(1)
                .context("missing PCK CA")?
                .to_der()?;
            let tcb_json: serde_json::Value = serde_json::from_str(&tcb)?;
            let eval = tcb_json["tcbInfo"]["tcbEvaluationDataNumber"]
                .as_u64()
                .context("missing TCB evaluation number")?;
            let fixture = V2Fixture {
                fixture_version: 1,
                source: args[3].clone(),
                quote_version: output.quote_version,
                verification_timestamp: timestamp,
                tcb_evaluation_data_number: eval.try_into()?,
                quote: hex_bytes(&quote),
                quote_sha256: sha256(&quote),
                root_ca_crl: hex_bytes(&root_crl),
                pck_crl: hex_bytes(&pck_crl),
                tcb_signing_certificate: hex_bytes(&chain[0]),
                root_ca_certificate: hex_bytes(&chain[1]),
                platform_ca_certificate: hex_bytes(&platform_ca),
                tcb_info_json: tcb,
                qe_identity_json: qe,
                guest_input: hex_bytes(&input),
                guest_input_sha256: sha256(&input),
                expected_journal: hex_bytes(&journal),
                expected_journal_sha256: sha256(&journal),
            };
            ensure!(
                fixture.rebuild_input()? == input,
                "capture round-trip mismatch"
            );
            let mut json = serde_json::to_string_pretty(&fixture)?;
            json.push('\n');
            write_new(&args[2], json.as_bytes())?;
            println!(
                "captured V{}; input_sha256={}; journal_bytes={}",
                output.quote_version,
                fixture.guest_input_sha256,
                journal.len()
            );
        },
        "export" => {
            ensure!(args.len() == 3, "export takes a fixture and destination");
            let fixture: V2Fixture = serde_json::from_slice(&std::fs::read(&args[1])?)?;
            let input = fixture.rebuild_input()?;
            ensure!(
                verify_guest_input_v2(&input)? == unhex(&fixture.expected_journal)?,
                "native journal mismatch"
            );
            write_new(&args[2], &input)?;
            println!(
                "exported V{}; input_sha256={}",
                fixture.quote_version,
                sha256(&input)
            );
        },
        _ => anyhow::bail!("unknown command"),
    }
    Ok(())
}
