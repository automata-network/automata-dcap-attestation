//! Resume a verified CPU core proof with pinned SP1 recursion/circuit parameters.
use anyhow::{ensure, Context, Result};
use sp1_prover::{SP1CoreProofData, SP1ProofWithMetadata};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use sp1_stark::MachineProver;
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
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 5 || args.len() == 6, "usage: sp1_v2_compress_local PROGRAM INPUT CORE_OR_COMPRESSED_PROOF NEW_DIR compressed|outer|groth16 [VERIFIED_OUTER_CHECKPOINT]");
    ensure!(
        matches!(args[4].as_str(), "compressed" | "outer" | "groth16"),
        "invalid stage"
    );
    ensure!(
        std::env::var_os("DEV_MODE").is_none(),
        "DEV_MODE must be unset"
    );
    for name in ["VERIFY_VK", "FIX_CORE_SHAPES", "FIX_RECURSION_SHAPES"] {
        ensure!(
            std::env::var(name).map_or(true, |v| v.eq_ignore_ascii_case("true")),
            "requires {name}=true"
        );
    }
    ensure!(
        std::env::var_os("FRI_QUERIES").is_none(),
        "FRI_QUERIES must be unset: official core/inner=100, shrink=50, outer=25"
    );
    std::env::set_var("SP1_DISABLE_PROGRAM_CACHE", "true");
    sp1_sdk::setup_logger();
    let output = Path::new(&args[3]);
    ensure!(!output.exists(), "output directory exists");
    let program = std::fs::read(&args[0])?;
    let input = std::fs::read(&args[1])?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input)?;
    let client = ProverClient::builder().cpu().build();
    let (_, vk) = client.setup(&program);
    println!("native_program_id={}", vk.bytes32());
    let source = SP1ProofWithPublicValues::load(&args[2])?;
    if args.len() == 6 {
        ensure!(
            args[4] == "groth16" && matches!(source.proof, SP1Proof::Compressed(_)),
            "outer resume requires the original compressed proof and groth16 stage"
        );
    }
    ensure!(
        matches!(source.proof, SP1Proof::Core(_) | SP1Proof::Compressed(_)),
        "real core/compressed proof required"
    );
    client
        .verify(&source, &vk)
        .context("source cryptographic verification")?;
    ensure!(
        source.public_values.as_slice() == expected,
        "source journal mismatch"
    );
    let version = source.sp1_version.clone();
    let public_values = source.public_values.clone();
    // Preserve the circuit/FRI parameters, bound only recursion buffering.
    let mut opts = sp1_stark::SP1ProverOpts::default();
    opts.recursion_opts.shard_batch_size = 1;
    opts.recursion_opts.trace_gen_workers = 1;
    opts.recursion_opts.checkpoints_channel_capacity = 1;
    opts.recursion_opts.records_and_traces_channel_capacity = 0;
    println!("recursion buffering: batch=1 workers=1 checkpoints=1 traces=rendezvous; circuit/FRI unchanged");
    let prover = client.inner();
    let reduced = match source.proof {
        SP1Proof::Core(shards) => {
            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&input);
            let (journal, report) = client.execute(&program, &stdin).run()?;
            ensure!(
                journal.as_slice() == expected,
                "reconstructed input execution mismatch"
            );
            let core = SP1ProofWithMetadata {
                proof: SP1CoreProofData(shards),
                stdin,
                public_values: public_values.clone(),
                cycles: report.total_instruction_count(),
            };
            prover
                .compress(&vk, core, vec![], opts)
                .context("local recursive compression")?
        }
        SP1Proof::Compressed(proof) => *proof,
        _ => unreachable!(),
    };
    let compressed = SP1ProofWithPublicValues {
        proof: SP1Proof::Compressed(Box::new(reduced.clone())),
        public_values: public_values.clone(),
        sp1_version: version.clone(),
        tee_proof: None,
    };
    client
        .verify(&compressed, &vk)
        .context("compressed cryptographic verification")?;
    std::fs::create_dir(output)?;
    write_new(
        &output.join("compressed.bin"),
        &bincode::serialize(&compressed)?,
    )?;
    println!(
        "compressed proof verification=PASS journal_bytes={}",
        expected.len()
    );
    if args[4] == "compressed" {
        return Ok(());
    }
    let outer = if let Some(checkpoint) = args.get(5) {
        // Derive the expected wrap key from the pinned SDK program. Never trust
        // a verifying key supplied inside an unverified checkpoint.
        let program = prover.wrap_program();
        let (_, expected_wrap_vk) = prover.wrap_prover.setup(&program);
        prover
            .wrap_vk
            .set(expected_wrap_vk)
            .map_err(|_| anyhow::anyhow!("wrap key already initialized"))?;
        bincode::deserialize(&std::fs::read(checkpoint)?)?
    } else {
        let shrink = prover.shrink(reduced, opts).context("shrink")?;
        prover
            .verify_shrink(&shrink, &vk)
            .context("shrink verification")?;
        write_new(&output.join("shrink.bin"), &bincode::serialize(&shrink)?)?;
        prover.wrap_bn254(shrink, opts).context("wrap bn254")?
    };
    prover
        .verify_wrap_bn254(&outer, &vk)
        .context("wrap verification")?;
    write_new(&output.join("outer.bin"), &bincode::serialize(&outer)?)?;
    if args[4] == "outer" {
        // Release recursion allocations before a separate gnark process. This
        // checkpoint is not an EVM proof; final SDK verification must still
        // bind the Groth16 public inputs to the expected complete journal.
        println!("BN254 wrap verification=PASS; saved checkpoint, Groth16 NOT_RUN");
        return Ok(());
    }
    let artifacts = sp1_sdk::install::groth16_circuit_artifacts_dir();
    ensure!(
        artifacts.is_dir(),
        "install the pinned official v5.0.0 Groth16 circuit artifacts first; never run a new setup"
    );
    let snark = prover.wrap_groth16_bn254(outer, &artifacts);
    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Groth16(snark),
        public_values,
        sp1_version: version,
        tee_proof: None,
    };
    client
        .verify(&proof, &vk)
        .context("Groth16 cryptographic verification")?;
    ensure!(
        proof.public_values.as_slice() == expected,
        "final journal mismatch"
    );
    write_new(&output.join("groth16.bin"), &bincode::serialize(&proof)?)?;
    let bytes = proof.bytes();
    ensure!(bytes.len() >= 4, "missing proof route selector");
    let payload = serde_json::json!({
        "backend": 2, "proofSystem": "groth16", "programId": vk.bytes32(),
        "journal": format!("0x{}", hex::encode(&expected)), "proof": format!("0x{}", hex::encode(&bytes)),
        "proofSelector": format!("0x{}", hex::encode(&bytes[..4])),
        "localVerification": "PASS", "forkVerification": "NOT_RUN"
    });
    write_new(
        &output.join("evm-proof.json"),
        &serde_json::to_vec_pretty(&payload)?,
    )?;
    println!("Groth16 cryptographic verification=PASS; fork acceptance remains required");
    Ok(())
}
