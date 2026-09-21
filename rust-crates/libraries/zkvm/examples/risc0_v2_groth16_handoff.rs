//! Split the pinned SDK's Docker stage across machines, then verify the returned
//! proof locally. Preparing witness files is NOT successful proof generation.
use anyhow::{ensure, Context, Result};
use automata_dcap_zkvm::{Risc0Prover, ZkVmProver};
use risc0_zkvm::{
    compute_image_id, sha::Digestible, ExternalProver, Groth16Receipt,
    Groth16ReceiptVerifierParameters, InnerReceipt, Prover, ProverOpts, Receipt,
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

fn main() -> Result<()> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    let minimal = args.last().is_some_and(|a| a == "--minimal");
    if minimal {
        args.pop();
    }
    ensure!(args.len() == 5 || args.len() == 6,
        "usage: risc0_v2_groth16_handoff prepare|import PROGRAM INPUT SUCCINCT_RECEIPT NEW_DIR [PROOF_JSON] [--minimal]");
    ensure!(
        (args[0] == "prepare" && args.len() == 5) || (args[0] == "import" && args.len() == 6),
        "invalid mode/arguments"
    );
    ensure!(
        !ProverOpts::default().dev_mode() && std::env::var_os("DEV_MODE").is_none(),
        "dev mode forbidden"
    );
    let output = Path::new(&args[4]);
    ensure!(!output.exists(), "output directory exists");
    let program = std::fs::read(&args[1])?;
    let id = compute_image_id(&program)?;
    ensure!(
        Risc0Prover::from_v2_elf(program)?.program_identifier()? == id.to_string(),
        "SDK image ID mismatch"
    );
    let input = std::fs::read(&args[2])?;
    let expected = if minimal {
        dcap_rs::v2::verify_guest_input_v2_minimal(&input)
    } else {
        dcap_rs::v2::verify_guest_input_v2(&input)
    }?;
    let source_bytes = std::fs::read(&args[3])?;
    let source: Receipt = bincode::deserialize(&source_bytes)?;
    source
        .verify(id)
        .context("source succinct cryptographic verification")?;
    ensure!(source.journal.bytes == expected, "source journal mismatch");
    let succinct = match &source.inner {
        InnerReceipt::Succinct(inner) => inner,
        _ => anyhow::bail!("verified succinct receipt required"),
    };
    let parameters = Groth16ReceiptVerifierParameters::default().digest();
    println!("native_program_id=0x{id} verifier_parameters={parameters}");
    if args[0] == "prepare" {
        let version = std::process::Command::new("r0vm")
            .arg("--version")
            .output()?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).trim() == "risc0-r0vm 3.0.3",
            "requires r0vm 3.0.3"
        );
        std::fs::create_dir(output)?;
        let absolute = output.canonicalize()?;
        write_new(&absolute.join("succinct.bin"), &source_bytes)?;
        // The unmodified SDK writes identity_p254 seal.r0/input.json BEFORE
        // starting Docker. Disable only this process's Docker connection, so it
        // returns those official witness files without launching the final
        // container. The final stage may run locally or on a second machine.
        // Never substitute a fake proof.
        std::env::set_var("RISC0_WORK_DIR", &absolute);
        std::env::remove_var("DOCKER_CONTEXT");
        std::env::set_var(
            "DOCKER_HOST",
            format!("unix://{}/intentionally-disabled.sock", absolute.display()),
        );
        let result = ExternalProver::new("prepare-groth16-witness", "r0vm")
            .compress(&ProverOpts::groth16(), &source);
        let error = result.expect_err("Docker must remain disabled during witness preparation");
        ensure!(
            error
                .to_string()
                .contains("docker returned failure exit code"),
            "unexpected preparation failure: {error:#}"
        );
        for name in ["seal.r0", "input.json"] {
            ensure!(
                absolute.join(name).metadata()?.len() > 0,
                "missing SDK-generated {name}"
            );
        }
        ensure!(
            !absolute.join("proof.json").exists(),
            "unexpected proof during preparation"
        );
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(absolute.join("input.json"))?)?;
        let manifest = serde_json::json!({
            "schema": 1, "status": "WITNESS_PREPARED_NOT_PROVEN", "backend": "risc0",
            "r0vmVersion": "3.0.3", "groth16ImageTag": "risczero/risc0-groth16-prover:v2025-04-03.1",
            "programId": format!("0x{id}"), "minCheck": minimal, "verifierParameters": parameters.to_string(),
            "journal": format!("0x{}", hex::encode(&expected)),
            "expectedDockerFailure": format!("{error:#}")
        });
        write_new(
            &absolute.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        println!("official SDK witness prepared; Groth16 proof and fork verification NOT_RUN");
        return Ok(());
    }
    let proof: risc0_groth16::ProofJson = serde_json::from_slice(&std::fs::read(&args[5])?)?;
    let seal: risc0_groth16::Seal = proof.try_into()?;
    let receipt = Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt::new(
            seal.to_vec(),
            succinct.claim.clone(),
            parameters,
        )),
        expected.clone(),
    );
    receipt
        .verify(id)
        .context("returned Groth16 cryptographic verification")?;
    let mut changed = receipt.clone();
    changed.journal.bytes[25] ^= 1;
    ensure!(changed.verify(id).is_err(), "modified journal accepted");
    ensure!(
        receipt.verify([0u32; 8]).is_err(),
        "wrong image ID accepted"
    );
    let mut changed = receipt.clone();
    if let InnerReceipt::Groth16(inner) = &mut changed.inner {
        inner.seal[0] ^= 1;
    }
    ensure!(changed.verify(id).is_err(), "modified seal accepted");
    let evm_seal = risc0_ethereum_contracts::encode_seal(&receipt)?;
    ensure!(evm_seal.len() == 260, "unexpected EVM seal length");
    std::fs::create_dir(output)?;
    write_new(&output.join("receipt.bin"), &bincode::serialize(&receipt)?)?;
    let payload = serde_json::json!({
        "backend": 1, "proofSystem": "groth16", "programId": format!("0x{id}"), "minCheck": minimal,
        "journal": format!("0x{}", hex::encode(&expected)), "proof": format!("0x{}", hex::encode(&evm_seal)),
        "proofSelector": format!("0x{}", hex::encode(&evm_seal[..4])),
        "localVerification": "PASS", "forkVerification": "NOT_RUN"
    });
    write_new(
        &output.join("evm-proof.json"),
        &serde_json::to_vec_pretty(&payload)?,
    )?;
    println!("returned Groth16: crypto/journal/tampering/wrong-ID PASS; fork acceptance remains required");
    Ok(())
}
