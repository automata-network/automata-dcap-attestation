//! Resume a real receipt through local recursion/Groth16; never use Bonsai or DEV_MODE.
use anyhow::{ensure, Context, Result};
use automata_dcap_zkvm::{Risc0Prover, ZkVmProver};
use risc0_zkvm::{
    compute_image_id, sha::Digest, ExternalProver, InnerReceipt, Prover, ProverOpts, Receipt,
};
use std::{io::Write, path::Path};

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn verify(receipt: &Receipt, id: Digest, expected: &[u8]) -> Result<()> {
    ensure!(
        !matches!(receipt.inner, InnerReceipt::Fake(_)),
        "fake receipt forbidden"
    );
    receipt
        .verify(id)
        .context("receipt cryptographic verification")?;
    ensure!(receipt.journal.bytes == expected, "journal mismatch");
    let mut changed = receipt.clone();
    changed.journal.bytes[25] ^= 1;
    ensure!(changed.verify(id).is_err(), "modified journal accepted");
    ensure!(
        receipt.verify(Digest::from([0u32; 8])).is_err(),
        "wrong image ID accepted"
    );
    let mut changed = receipt.clone();
    match &mut changed.inner {
        InnerReceipt::Composite(r) => r.segments[0].seal[0] ^= 1,
        InnerReceipt::Succinct(r) => r.seal[0] ^= 1,
        InnerReceipt::Groth16(r) => r.seal[0] ^= 1,
        _ => anyhow::bail!("unsupported receipt kind"),
    }
    ensure!(changed.verify(id).is_err(), "modified seal accepted");
    println!("receipt-crypto,journal-parity,modified-journal,wrong-image-id,modified-seal PASS");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5,
        "usage: risc0_v2_compress_local PROGRAM INPUT RECEIPT NEW_DIR succinct|groth16|export"
    );
    ensure!(
        !ProverOpts::default().dev_mode(),
        "RISC0_DEV_MODE must be disabled"
    );
    ensure!(
        std::env::var_os("DEV_MODE").is_none(),
        "DEV_MODE must be unset"
    );
    ensure!(
        matches!(args[4].as_str(), "succinct" | "groth16" | "export"),
        "invalid mode"
    );
    let output = Path::new(&args[3]);
    ensure!(!output.exists(), "output directory exists");
    let program = std::fs::read(&args[0])?;
    let id = compute_image_id(&program)?;
    let sdk = Risc0Prover::from_v2_elf(program)?;
    ensure!(
        sdk.program_identifier()? == id.to_string(),
        "SDK image ID mismatch"
    );
    println!("SDK canonical-program loading=PASS native_program_id=0x{id}");
    let input = std::fs::read(&args[1])?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input)?;
    let source: Receipt = bincode::deserialize(&std::fs::read(&args[2])?)?;
    verify(&source, id, &expected)?;
    let receipt = if args[4] == "export" {
        ensure!(
            matches!(source.inner, InnerReceipt::Groth16(_)),
            "export requires a Groth16 receipt"
        );
        source
    } else {
        let version = std::process::Command::new("r0vm")
            .arg("--version")
            .output()?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).trim() == "risc0-r0vm 3.0.3",
            "requires r0vm 3.0.3"
        );
        let opts = if args[4] == "succinct" {
            ProverOpts::succinct()
        } else {
            ProverOpts::groth16()
        };
        println!("compression={} local-r0vm; no remote proving", args[4]);
        ExternalProver::new("local-compression", "r0vm").compress(&opts, &source)?
    };
    verify(&receipt, id, &expected)?;
    std::fs::create_dir(output)?;
    write_new(&output.join("receipt.bin"), &bincode::serialize(&receipt)?)?;
    if matches!(receipt.inner, InnerReceipt::Groth16(_)) {
        let seal = risc0_ethereum_contracts::encode_seal(&receipt)?;
        ensure!(seal.len() == 260, "unexpected Groth16 EVM seal length");
        let payload = serde_json::json!({
            "backend": 1, "proofSystem": "groth16", "programId": format!("0x{id}"),
            "journal": format!("0x{}", hex::encode(expected)), "proof": format!("0x{}", hex::encode(&seal)),
            "proofSelector": format!("0x{}", hex::encode(&seal[..4])),
            "localVerification": "PASS", "forkVerification": "NOT_RUN"
        });
        write_new(
            &output.join("evm-proof.json"),
            &serde_json::to_vec_pretty(&payload)?,
        )?;
        println!(
            "EVM Groth16 payload saved; fork universal-verifier/FeeV2 acceptance remains required"
        );
    }
    println!("saved={} mode={}", output.display(), args[4]);
    Ok(())
}
