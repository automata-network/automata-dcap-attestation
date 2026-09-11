//! Local SP1 V2 execution, native journal parity and optional rejection checks.
//! This does not generate proofs, contact a prover network or register a program.
use alloy_sol_types::{sol, SolType};
use anyhow::{ensure, Context, Result};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, SP1_CIRCUIT_VERSION};

type GuestInput = sol!((bytes, bytes, uint64));
const EXECUTION_CYCLE_LIMIT: u64 = 500_000_000;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--negative"),
        "usage: sp1_v2_execute <ELF> <V2 ABI input> [--negative]"
    );
    let elf = std::fs::read(&args[0]).context("read ELF")?;
    let input = std::fs::read(&args[1]).context("read V2 ABI input")?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input).context("native V2 verification")?;

    // Explicitly select CPU: ignore SP1_PROVER/DEV_MODE and never use the network prover.
    // Execution and the native core VK do not need cached recursive proof programs.
    // This saves memory without disabling VK verification or changing circuit shapes.
    std::env::set_var("SP1_DISABLE_PROGRAM_CACHE", "true");
    for name in ["VERIFY_VK", "FIX_CORE_SHAPES", "FIX_RECURSION_SHAPES"] {
        ensure!(
            std::env::var(name).map_or(true, |value| value.eq_ignore_ascii_case("true")),
            "execution checks require the default {name}=true setting"
        );
    }
    let client = ProverClient::builder().cpu().build();
    let (_, vk) = client.setup(&elf);
    println!("circuit_version={}", SP1_CIRCUIT_VERSION.trim());
    println!("native_program_id={}", vk.bytes32());
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (journal, report) = client
        .execute(&elf, &stdin)
        .cycle_limit(EXECUTION_CYCLE_LIMIT)
        .run()
        .context("SP1 execution")?;
    ensure!(
        journal.as_slice() == expected,
        "SP1/native V2 journal mismatch"
    );
    let parsed = automata_dcap_zkvm::parse_output_v2(journal.as_slice())
        .context("SDK V2 journal decoding")?;
    println!(
        "cycles={} journal_bytes={} parity=PASS",
        report.total_instruction_count(),
        journal.as_slice().len()
    );
    println!(
        "quote_version={} output_format={}.{} piid_present={}",
        parsed.quote_version,
        parsed.format_major_version,
        parsed.format_minor_version,
        parsed.piid_present
    );

    if args.len() == 3 {
        let (collateral, quote, timestamp) = GuestInput::abi_decode_params(&input)?;
        ensure!(
            quote.len() > 80,
            "quote is too short for signed-body mutation"
        );
        let mut tampered = quote.to_vec();
        tampered[80] ^= 1;
        for (name, invalid) in [
            (
                "tampered-signed-body",
                GuestInput::abi_encode_params(&(collateral.clone(), tampered, timestamp)),
            ),
            (
                "pre-validity-timestamp",
                GuestInput::abi_encode_params(&(collateral, quote, 0u64)),
            ),
        ] {
            ensure!(
                dcap_rs::v2::verify_guest_input_v2(&invalid).is_err(),
                "native V2 unexpectedly accepted {name}"
            );
            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&invalid);
            let result = client
                .execute(&elf, &stdin)
                .cycle_limit(EXECUTION_CYCLE_LIMIT)
                .run();
            let error = result.expect_err("SP1 V2 unexpectedly accepted invalid input");
            // The guest's validation .expect() must panic with exit code 1.
            // A cycle limit or unsupported syscall must NOT count as rejection.
            ensure!(
                error.root_cause().to_string() == "execution failed with exit code 1",
                "unexpected SP1 failure for {name}: {error:#}"
            );
            println!("rejection={name} native_and_guest=PASS");
        }
    }
    println!("Execution only: no proof generated or universal verifier checked.");
    Ok(())
}
