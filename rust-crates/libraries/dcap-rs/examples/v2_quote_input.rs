//! Explicit public-quote inspection/preparation; never normalizes verification input implicitly.
#[path = "../tests/support/v2_fixture.rs"]
mod fixture;

use alloy_sol_types::SolType;
use anyhow::{Context, Result, ensure};
use dcap_rs::{types::quote::Quote, v2::verify_guest_input_v2};
use fixture::{GuestInput, V2Fixture, hex_bytes, sha256, unhex};
use std::io::Write;

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
        args.len() >= 2,
        "usage: v2_quote_input inspect QUOTE.hex | extract-zero-padding QUOTE.hex OUTPUT.hex | prepare QUOTE.hex SNAPSHOT.json TCB.json QE.json TIMESTAMP OUTPUT.bin"
    );
    let raw = unhex(std::fs::read_to_string(&args[1])?.trim())?;
    let mut remaining = raw.as_slice();
    let quote = Quote::read(&mut remaining)?;
    let chain = quote.signature.get_pck_cert_chain()?;
    let ext = &chain.pck_extension;
    println!(
        "quote_version={} body_type={} quote_bytes={} parsed_bytes={} trailing_bytes={} quote_sha256={}",
        quote.header.version.get(),
        quote.body_type,
        raw.len(),
        raw.len() - remaining.len(),
        remaining.len(),
        sha256(&raw)
    );
    println!(
        "fmspc={} ppid={} piid={} piid_present={}",
        hex::encode(ext.fmspc),
        hex::encode(ext.ppid),
        hex::encode(ext.platform_instance_id().unwrap_or([0; 16])),
        ext.platform_instance_id().is_some()
    );
    match args[0].as_str() {
        "inspect" => {
            ensure!(args.len() == 2, "inspect takes one quote path");
            dcap_rs::verify_quote_signatures(&quote)?;
            println!("quote_signatures=PASS (not full collateral/production-policy verification)");
        },
        "extract-zero-padding" => {
            ensure!(args.len() == 3, "extraction takes input and output paths");
            ensure!(
                !remaining.is_empty() && remaining.iter().all(|b| *b == 0),
                "requires a nonempty all-zero suffix"
            );
            dcap_rs::verify_quote_signatures(&quote)?;
            let prefix = &raw[..raw.len() - remaining.len()];
            let mut parsed = prefix;
            Quote::read(&mut parsed)?;
            ensure!(parsed.is_empty(), "extracted prefix is not exact");
            write_new(&args[2], format!("{}\n", hex_bytes(prefix)).as_bytes())?;
            println!(
                "explicit_extracted_sha256={}; original remains unchanged",
                sha256(prefix)
            );
        },
        "prepare" => {
            ensure!(
                args.len() == 7,
                "prepare requires quote, snapshot, signed TCB/QE JSON, timestamp and output"
            );
            ensure!(
                remaining.is_empty(),
                "trailing bytes after quote; extraction must be explicit"
            );
            let snapshot: V2Fixture = serde_json::from_slice(&std::fs::read(&args[2])?)?;
            let base = snapshot.rebuild_input()?;
            let (collateral, _, _) = GuestInput::abi_decode_params(&base)?;
            let (root, pck, signing, _, _) =
                dcap_rs::types::collateral::CollateralSol::abi_decode_params(&collateral)?;
            let tcb = std::fs::read_to_string(&args[3])?;
            let qe = std::fs::read_to_string(&args[4])?;
            let collateral = dcap_rs::types::collateral::CollateralSol::abi_encode_params(&(
                root, pck, signing, tcb, qe,
            ));
            let timestamp: u64 = args[5].parse().context("timestamp")?;
            let input = GuestInput::abi_encode_params(&(collateral, raw, timestamp));
            let journal = verify_guest_input_v2(&input).context("native V2 verification")?;
            write_new(&args[6], &input)?;
            println!(
                "native_v2=PASS input_sha256={} journal_bytes={} journal_sha256={}",
                sha256(&input),
                journal.len(),
                sha256(&journal)
            );
        },
        _ => anyhow::bail!("unknown command"),
    }
    Ok(())
}
