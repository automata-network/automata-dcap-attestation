//! Execute an explicit Pico V2 ELF and compare its journal to native verification.
//! This is an execution check, NOT a proof or universal-verifier compatibility test.
use anyhow::{ensure, Context, Result};
use p3_field::PrimeField;
use pico_sdk::{client::KoalaBearProverClient, HashableKey};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: pico_v2_execute <ELF> <V2 ABI input>"
    );
    let elf = std::fs::read(&args[0]).context("read ELF")?;
    let input = std::fs::read(&args[1]).context("read V2 ABI input")?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input).context("native V2 verification")?;

    let client = KoalaBearProverClient::new(&elf);
    let id = client
        .riscv_vk()
        .hash_bn254()
        .as_canonical_biguint()
        .to_bytes_be();
    ensure!(id.len() <= 32, "native program ID exceeds 32 bytes");
    println!("native_program_id=0x{:0>64}", hex::encode(id));
    let mut stdin = client.new_stdin_builder();
    stdin.write_slice(&input);
    let (cycles, journal) = client.emulate(stdin);
    ensure!(journal == expected, "Pico/native V2 journal mismatch");
    println!(
        "cycles={cycles} journal_bytes={} parity=PASS",
        journal.len()
    );
    println!("Execution only: no proof generated or universal verifier checked.");
    Ok(())
}
