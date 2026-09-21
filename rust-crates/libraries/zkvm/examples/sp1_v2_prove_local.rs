//! SP1 6.8.0 local CPU proof generation/verification. Never selects a remote prover.
//! Only verified Groth16/Plonk proofs are exported as EVM calldata.
use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Kind {
    Core,
    Compressed,
    Groth16,
    Plonk,
}

#[derive(Parser)]
struct Args {
    program: PathBuf,
    input: PathBuf,
    proof: PathBuf,
    #[arg(long, value_enum, default_value = "core")]
    kind: Kind,
    #[arg(long)]
    minimal: bool,
    /// Verify an existing v6 proof instead of generating one.
    #[arg(long)]
    verify: bool,
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        std::env::var_os("DEV_MODE").is_none(),
        "DEV_MODE must be unset"
    );
    // These historical overrides must not silently carry into v6 proving.
    for name in ["FRI_QUERIES", "DCAP_SP1_SHARD_SIZE", "SP1_DEV_MODE"] {
        ensure!(
            std::env::var_os(name).is_none(),
            "unset obsolete/unsafe {name}; use reviewed v6 defaults"
        );
    }
    for name in ["VERIFY_VK", "FIX_CORE_SHAPES", "FIX_RECURSION_SHAPES"] {
        ensure!(
            std::env::var(name).map_or(true, |v| v.eq_ignore_ascii_case("true")),
            "requires {name}=true"
        );
    }
    let program = std::fs::read(&args.program)?;
    automata_dcap_zkvm::sp1::prover::validate_v6_elf(&program)?;
    let input = std::fs::read(&args.input)?;
    let expected = if args.minimal {
        dcap_rs::v2::verify_guest_input_v2_minimal(&input)
    } else {
        dcap_rs::v2::verify_guest_input_v2(&input)
    }?;
    let evm_file = args.proof.with_extension("evm.json");
    let evm_kind = matches!(args.kind, Kind::Groth16 | Kind::Plonk);
    if !args.verify {
        ensure!(!args.proof.exists(), "proof output exists");
        if evm_kind {
            ensure!(!evm_file.exists(), "EVM output exists");
        }
    }
    sp1_sdk::setup_logger();
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(Elf::from(program)).await?;
    let vk = pk.verifying_key();
    println!(
        "sdk=6.8.0 native_program_id={} min_check={}",
        vk.bytes32(),
        args.minimal
    );
    let proof = if args.verify {
        SP1ProofWithPublicValues::load(&args.proof)?
    } else {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let request = client.prove(&pk, stdin);
        match args.kind {
            Kind::Core => request.core().await,
            Kind::Compressed => request.compressed().await,
            Kind::Groth16 => request.groth16().await,
            Kind::Plonk => request.plonk().await,
        }
        .context("local SP1 v6 proving")?
    };
    ensure!(
        match (&proof.proof, args.kind) {
            (SP1Proof::Core(shards), Kind::Core) => !shards.is_empty(),
            (SP1Proof::Compressed(_), Kind::Compressed)
            | (SP1Proof::Groth16(_), Kind::Groth16)
            | (SP1Proof::Plonk(_), Kind::Plonk) => true,
            _ => false,
        },
        "unexpected proof kind/empty proof"
    );
    client
        .verify(&proof, vk, None)
        .context("proof cryptography and successful guest exit")?;
    ensure!(
        proof.public_values.as_slice() == expected,
        "journal mismatch"
    );
    let mut tampered = proof.clone();
    let mut journal = expected.clone();
    journal[25] ^= 1;
    tampered.public_values = SP1PublicValues::from(&journal);
    ensure!(
        client.verify(&tampered, vk, None).is_err(),
        "modified journal accepted"
    );
    let mut wrong_vk = vk.clone();
    wrong_vk.vk.pc_start = Default::default();
    ensure!(
        wrong_vk.bytes32() != vk.bytes32(),
        "ineffective wrong-key mutation"
    );
    ensure!(
        client.verify(&proof, &wrong_vk, None).is_err(),
        "wrong key accepted"
    );
    if let SP1Proof::Core(shards) = &proof.proof {
        let mut changed = shards.clone();
        let mut commitment = changed[0].main_commitment;
        let element = commitment
            .iter_mut()
            .find(|v| **v != Default::default())
            .context("all-zero commitment")?;
        *element = Default::default();
        changed[0].main_commitment = commitment;
        let mut tampered = proof.clone();
        tampered.proof = SP1Proof::Core(changed);
        ensure!(
            client.verify(&tampered, vk, None).is_err(),
            "modified core proof accepted"
        );
        println!("rejection=modified-core-commitment PASS");
    }
    println!(
        "real_proof=PASS journal_bytes={} rejection=modified-journal,wrong-key PASS",
        expected.len()
    );
    if !args.verify {
        write_new(&args.proof, &bincode::serialize(&proof)?)?;
        if evm_kind {
            let bytes = proof.bytes();
            ensure!(
                bytes.len() > 4 && proof.tee_proof.is_none(),
                "expected nonempty standard EVM proof"
            );
            let payload = serde_json::json!({
                "backend": 2, "buildSdkVersion": "6.8.0", "programId": vk.bytes32(),
                "minCheck": args.minimal, "proofSystem": if matches!(args.kind, Kind::Groth16) { "groth16" } else { "plonk" },
                "journal": format!("0x{}", hex::encode(&expected)),
                "proof": format!("0x{}", hex::encode(&bytes)),
                "proofSelector": format!("0x{}", hex::encode(&bytes[..4])),
                "localVerification": "PASS", "forkVerification": "NOT_RUN"
            });
            write_new(&evm_file, &serde_json::to_vec_pretty(&payload)?)?;
        }
    }
    println!("Local proof only: universal verifier/AttestationV2 acceptance remains required.");
    Ok(())
}
