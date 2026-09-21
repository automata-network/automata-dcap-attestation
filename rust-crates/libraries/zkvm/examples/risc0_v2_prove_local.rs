//! Real local composite receipt, not an EVM Groth16 proof or a remote request.
use anyhow::{ensure, Context, Result};
use risc0_zkvm::{
    compute_image_id, sha::Digest, ExecutorEnv, ExternalProver, InnerReceipt, Prover, ProverOpts,
    Receipt,
};
use std::io::Write;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        (3..=5).contains(&args.len())
            && args[3..]
                .iter()
                .all(|a| a == "--verify" || a == "--minimal"),
        "usage: risc0_v2_prove_local PROGRAM INPUT RECEIPT [--verify] [--minimal]"
    );
    ensure!(
        !ProverOpts::default().dev_mode(),
        "RISC0_DEV_MODE must be disabled"
    );
    let elf = std::fs::read(&args[0])?;
    let input = std::fs::read(&args[1])?;
    let minimal = args.iter().any(|a| a == "--minimal");
    let verify_only = args.iter().any(|a| a == "--verify");
    let expected = if minimal {
        dcap_rs::v2::verify_guest_input_v2_minimal(&input)
    } else {
        dcap_rs::v2::verify_guest_input_v2(&input)
    }?;
    let id = compute_image_id(&elf)?;
    println!("native_program_id=0x{id}");
    println!("min_check={minimal}");
    let receipt: Receipt = if verify_only {
        bincode::deserialize(&std::fs::read(&args[2])?)?
    } else {
        ensure!(!std::path::Path::new(&args[2]).exists(), "output exists");
        let version = std::process::Command::new("r0vm")
            .arg("--version")
            .output()?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).trim() == "risc0-r0vm 3.0.3",
            "requires r0vm 3.0.3"
        );
        let env = ExecutorEnv::builder()
            .write_slice(&input)
            .segment_limit_po2(18)
            .session_limit(Some(500_000_000))
            .build()?;
        println!("proving=local-composite segment_po2=18 (not an EVM seal)");
        ExternalProver::new("local-proving", "r0vm")
            .prove_with_opts(env, &elf, &ProverOpts::composite())
            .context("local composite proving")?
            .receipt
    };
    ensure!(
        matches!(&receipt.inner, InnerReceipt::Composite(_)),
        "expected a real composite receipt, never fake"
    );
    receipt
        .verify(id)
        .context("receipt cryptographic verification")?;
    ensure!(receipt.journal.bytes == expected, "journal mismatch");
    println!(
        "real_composite_receipt=PASS journal_bytes={}",
        expected.len()
    );
    let mut tampered = receipt.clone();
    tampered.journal.bytes[25] ^= 1;
    ensure!(tampered.verify(id).is_err(), "modified journal accepted");
    ensure!(
        receipt.verify(Digest::from([0u32; 8])).is_err(),
        "wrong image ID accepted"
    );
    let mut tampered = receipt.clone();
    if let InnerReceipt::Composite(inner) = &mut tampered.inner {
        inner.segments[0].seal[0] ^= 1;
    }
    ensure!(tampered.verify(id).is_err(), "modified seal accepted");
    println!("rejection=modified-journal,wrong-image-id,modified-seal PASS");
    if !verify_only {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])?
            .write_all(&bincode::serialize(&receipt)?)?;
    }
    println!("EVM Groth16 compression/universal verifier/AttestationV2 remain untested.");
    Ok(())
}
