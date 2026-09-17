//! Real local CPU core proof, not an EVM Groth16/Plonk proof or a network request.
use anyhow::{ensure, Context, Result};
use sp1_sdk::{
    HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues,
    SP1Stdin,
};
use std::io::Write;

fn parse_shard_size(value: &str) -> Result<usize> {
    let size: usize = value.parse().context("invalid DCAP_SP1_SHARD_SIZE")?;
    ensure!(
        matches!(size, 65536 | 131072 | 262144),
        "DCAP_SP1_SHARD_SIZE must be 65536, 131072, or 262144"
    );
    Ok(size)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3 || (args.len() == 4 && args[3] == "--verify"),
        "usage: sp1_v2_prove_local PROGRAM INPUT PROOF [--verify]"
    );
    ensure!(
        std::env::var_os("DEV_MODE").is_none(),
        "DEV_MODE must be unset"
    );
    for name in ["VERIFY_VK", "FIX_CORE_SHAPES", "FIX_RECURSION_SHAPES"] {
        ensure!(
            std::env::var(name).map_or(true, |s| s.eq_ignore_ascii_case("true")),
            "requires default {name}=true"
        );
    }
    ensure!(
        std::env::var_os("FRI_QUERIES").is_none(),
        "FRI_QUERIES must be unset: official core/inner=100, shrink=50, outer=25"
    );
    // SDK-supported execution partitioning only. Do not change FRI, VK checks,
    // the program, or the verifier's allowed shapes to reduce memory usage.
    let shard_size = match std::env::var("DCAP_SP1_SHARD_SIZE") {
        Ok(value) => parse_shard_size(&value)?,
        Err(std::env::VarError::NotPresent) => 1 << 18,
        Err(error) => return Err(error.into()),
    };
    // Core proving does not need the recursive-program cache. This is not a VK bypass.
    std::env::set_var("SP1_DISABLE_PROGRAM_CACHE", "true");
    sp1_sdk::setup_logger();
    let elf = std::fs::read(&args[0])?;
    let input = std::fs::read(&args[1])?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input)?;
    if args.len() == 3 {
        ensure!(!std::path::Path::new(&args[2]).exists(), "output exists");
    }
    let client = ProverClient::builder().cpu().build();
    let (pk, vk) = client.setup(&elf);
    println!("native_program_id={}", vk.bytes32());
    let proof: SP1ProofWithPublicValues = if args.len() == 4 {
        SP1ProofWithPublicValues::load(&args[2])?
    } else {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        println!(
            "proving=local-cpu-core shard_size={shard_size} shard_batch_size=1 (not an EVM proof)"
        );
        client
            .prove(&pk, &stdin)
            .core()
            .shard_size(shard_size)
            .shard_batch_size(1)
            .cycle_limit(500_000_000)
            .run()
            .context("local SP1 core proving")?
    };
    ensure!(
        matches!(&proof.proof, SP1Proof::Core(shards) if !shards.is_empty()),
        "expected nonempty real core proof"
    );
    client
        .verify(&proof, &vk)
        .context("core proof cryptographic verification")?;
    ensure!(
        proof.public_values.as_slice() == expected,
        "journal mismatch"
    );
    println!("real_core_proof=PASS journal_bytes={}", expected.len());
    let mut tampered = proof.clone();
    let mut journal = expected;
    journal[25] ^= 1;
    tampered.public_values = SP1PublicValues::from(&journal);
    ensure!(
        client.verify(&tampered, &vk).is_err(),
        "modified journal accepted"
    );
    let mut wrong_vk = vk.clone();
    wrong_vk.vk.pc_start = Default::default();
    ensure!(
        wrong_vk.bytes32() != vk.bytes32(),
        "wrong VK mutation was ineffective"
    );
    ensure!(
        client.verify(&proof, &wrong_vk).is_err(),
        "wrong VK accepted"
    );
    let mut tampered = proof.clone();
    if let SP1Proof::Core(shards) = &mut tampered.proof {
        let mut commitment = *shards[0].commitment.main_commit.as_ref();
        let element = commitment
            .iter_mut()
            .find(|value| **value != Default::default())
            .context("unexpected all-zero proof commitment")?;
        *element = Default::default();
        shards[0].commitment.main_commit = commitment.into();
    }
    ensure!(
        client.verify(&tampered, &vk).is_err(),
        "modified proof commitment accepted"
    );
    println!("rejection=modified-journal,wrong-vkey,modified-proof-commitment PASS");
    if args.len() == 3 {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])?
            .write_all(&bincode::serialize(&proof)?)?;
    }
    println!("EVM Groth16/Plonk compression/universal verifier/FeeV2 remain untested.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_shard_size;

    #[test]
    fn accepts_only_supported_small_shards() {
        for value in ["65536", "131072", "262144"] {
            assert_eq!(parse_shard_size(value).unwrap().to_string(), value);
        }
    }

    #[test]
    fn rejects_invalid_or_larger_shards() {
        for value in ["", "0", "-1", "17", "131073", "524288", "invalid"] {
            assert!(parse_shard_size(value).is_err(), "{value}");
        }
    }
}
