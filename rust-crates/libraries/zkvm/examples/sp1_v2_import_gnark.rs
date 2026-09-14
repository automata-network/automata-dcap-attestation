//! Import the pinned official gnark container's result after standalone proving.
//! Reverify the original compressed proof and bind Groth16 to its full journal.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use serde::Deserialize;
use sp1_sdk::{
    HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues,
};
use sp1_stark::{Groth16Bn254Proof, PlonkBn254Proof};
use std::{io::Write, path::Path};

// Exact bincode variant order of sp1-recursion-gnark-ffi 5.2.2::ProofBn254.
// This is container transport, not SP1Proof's different discriminant layout.
#[derive(Deserialize)]
#[allow(dead_code)]
enum ContainerProof {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 5, "usage: sp1_v2_import_gnark PROGRAM INPUT VERIFIED_COMPRESSED RAW_GNARK_RESULT NEW_DIRECTORY");
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
    let output = Path::new(&args[4]);
    ensure!(!output.exists(), "output directory already exists");
    let expected = dcap_rs::v2::verify_guest_input_v2(&std::fs::read(&args[1])?)?;
    let client = ProverClient::builder().cpu().build();
    let (_, vk) = client.setup(&std::fs::read(&args[0])?);
    println!("native_program_id={}", vk.bytes32());
    let source = SP1ProofWithPublicValues::load(&args[2])?;
    ensure!(
        matches!(source.proof, SP1Proof::Compressed(_)),
        "expected original real compressed proof"
    );
    client
        .verify(&source, &vk)
        .context("original compressed cryptography")?;
    ensure!(
        source.public_values.as_slice() == expected,
        "original full journal mismatch"
    );

    // Bounded, strict transport decoding; neither a success log nor an outer
    // checkpoint is a substitute for this final proof verification.
    ensure!(
        std::fs::metadata(&args[3])?.len() <= 65536,
        "oversized gnark result"
    );
    let decoded: ContainerProof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(65536)
        .reject_trailing_bytes()
        .deserialize(&std::fs::read(&args[3])?)?;
    let ContainerProof::Groth16(mut snark) = decoded else {
        anyhow::bail!("expected Groth16, not Plonk");
    };
    ensure!(
        snark.encoded_proof.len() == 512 && hex::decode(&snark.encoded_proof)?.len() == 256,
        "unexpected EVM proof encoding"
    );
    // The SDK normally attaches this after Docker returns. Pin the existing
    // official v5.0.0 VK; SDK verification also hashes the actual local VK file.
    snark.groth16_vkey_hash =
        hex::decode("a4594c59bbc142f3b81c3ecb7f50a7c34bc9af7c4c444b5d48b795427e285913")?
            .try_into()
            .expect("fixed 32-byte VK hash");
    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Groth16(snark),
        public_values: source.public_values,
        sp1_version: source.sp1_version,
        tee_proof: None,
    };
    client
        .verify(&proof, &vk)
        .context("Groth16 cryptography and expected public input binding")?;
    ensure!(
        proof.public_values.as_slice() == expected,
        "final full journal mismatch"
    );
    let mut changed = proof.clone();
    let mut journal = expected.clone();
    journal[25] ^= 1;
    changed.public_values = SP1PublicValues::from(&journal);
    ensure!(
        client.verify(&changed, &vk).is_err(),
        "modified journal accepted"
    );
    let mut wrong_vk = vk.clone();
    wrong_vk.vk.pc_start = Default::default();
    ensure!(
        wrong_vk.bytes32() != vk.bytes32(),
        "ineffective wrong-key mutation"
    );
    ensure!(
        client.verify(&proof, &wrong_vk).is_err(),
        "wrong program key accepted"
    );
    let mut changed = proof.clone();
    if let SP1Proof::Groth16(ref mut snark) = changed.proof {
        let mut raw = hex::decode(&snark.raw_proof)?;
        ensure!(!raw.is_empty(), "empty raw proof");
        raw[0] ^= 1;
        snark.raw_proof = hex::encode(raw);
    }
    ensure!(
        client.verify(&changed, &vk).is_err(),
        "modified raw proof accepted"
    );
    client
        .verify(&proof, &vk)
        .context("positive cryptographic control after rejection checks")?;
    let bytes = proof.bytes();
    ensure!(
        bytes.len() == 260 && bytes[..4] == [0xa4, 0x59, 0x4c, 0x59],
        "unexpected EVM route/length"
    );
    let payload = serde_json::json!({
        "backend": 2, "proofSystem": "groth16", "programId": vk.bytes32(),
        "journal": format!("0x{}", hex::encode(&expected)),
        "proof": format!("0x{}", hex::encode(bytes)), "proofSelector": "0xa4594c59",
        "localVerification": "PASS", "forkVerification": "NOT_RUN"
    });
    std::fs::create_dir(output)?;
    write_new(&output.join("groth16.bin"), &bincode::serialize(&proof)?)?;
    write_new(
        &output.join("evm-proof.json"),
        &serde_json::to_vec_pretty(&payload)?,
    )?;
    println!("Groth16 cryptography=PASS journal_bytes={} modified-journal/wrong-key/modified-raw-proof=REJECTED; EVM bytes still require fork verification", expected.len());
    Ok(())
}
