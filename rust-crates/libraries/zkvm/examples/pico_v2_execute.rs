//! Execute an explicit Pico V2 ELF and compare its journal to native verification.
//! This is an execution check, NOT a proof or universal-verifier compatibility test.
use anyhow::{Context, Result, ensure};
use p3_field::PrimeField;
use pico_sdk::{HashableKey, client::KoalaBearProverClient};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2
            || (args.len() == 3 && (args[2] == "--minimal" || args[2] == "--expect-reject")),
        "usage: pico_v2_execute <ELF> <V2 ABI input> [--minimal] [--expect-reject]"
    );
    let expect_reject = args.iter().any(|a| a == "--expect-reject");
    let elf = std::fs::read(&args[0]).context("read ELF")?;
    let input = std::fs::read(&args[1]).context("read V2 ABI input")?;
    let minimal = args.iter().any(|a| a == "--minimal");
    let verify = if minimal {
        dcap_rs::v2::verify_guest_input_v2_minimal
    } else {
        dcap_rs::v2::verify_guest_input_v2
    };

    let client = KoalaBearProverClient::new(&elf);
    let id = client
        .riscv_vk()
        .hash_bn254()
        .as_canonical_biguint()
        .to_bytes_be();
    ensure!(id.len() <= 32, "native program ID exceeds 32 bytes");
    println!("native_program_id=0x{:0>64}", hex::encode(id));

    // Mode-divergent policy fixtures (e.g. the Alibaba migration-service quote)
    // must be rejected natively in this mode and rejected by the guest as well.
    // Pico's emulator propagates a failing guest as a host panic on the internal
    // EmulationError unwrap; catch it and require a genuine non-zero guest halt.
    if expect_reject {
        let rejection = verify(&input).expect_err("native V2 unexpectedly accepted policy input");
        println!("mode={}", if minimal { "minimal" } else { "strict" });
        println!("native_rejection={rejection}");
        let mut stdin = client.new_stdin_builder();
        stdin.write_slice(&input);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.emulate(stdin)
        }));
        let error = outcome.expect_err("Pico V2 unexpectedly accepted policy input");
        let message = error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        // The SDK emulator unwraps a failing guest into a host panic whose
        // payload carries the Debug-formatted EmulationError. Require the
        // specific non-zero guest halt; cycle limits, faults and transport
        // errors are not validation rejections.
        ensure!(
            message.contains("HaltWithNonZeroExitCode("),
            "unexpected Pico policy rejection panic: {message}"
        );
        println!("policy_rejection=native_and_guest=PASS");
        println!("Execution only: no proof generated or universal verifier checked.");
        return Ok(());
    }

    let expected = verify(&input).context("native V2 verification")?;
    println!("mode={}", if minimal { "minimal" } else { "strict" });
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
