//! Local RISC Zero V2 execution, journal parity and optional rejection checks.
//! This does not generate receipts, contact Bonsai or register a program.
#[path = "../../dcap-rs/tests/support/v2_negative_cases.rs"]
mod negative_cases;
use anyhow::{ensure, Context, Result};
use risc0_zkvm::{compute_image_id, Executor, ExecutorEnv, ExitCode, ExternalProver};

const EXECUTION_CYCLE_LIMIT: u64 = 500_000_000;

fn execution_env(input: &[u8]) -> Result<ExecutorEnv<'_>> {
    ExecutorEnv::builder()
        .write_slice(input)
        .session_limit(Some(EXECUTION_CYCLE_LIMIT))
        .build()
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--negative"),
        "usage: risc0_v2_execute <V2 program binary> <V2 ABI input> [--negative]"
    );
    ensure!(
        !risc0_zkvm::ProverOpts::default().dev_mode(),
        "RISC0_DEV_MODE must be disabled for validation"
    );
    let version = std::process::Command::new("r0vm")
        .arg("--version")
        .output()
        .context("r0vm 3.0.3 must be installed")?;
    ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).trim() == "risc0-r0vm 3.0.3",
        "local validation requires r0vm 3.0.3"
    );
    let elf = std::fs::read(&args[0]).context("read V2 program binary")?;
    let input = std::fs::read(&args[1]).context("read V2 ABI input")?;
    let expected = dcap_rs::v2::verify_guest_input_v2(&input).context("native V2 verification")?;

    // Explicit local subprocess: never select Bonsai or a prover from environment.
    // Only Executor::execute is called, not Prover::prove or a DEV_MODE receipt.
    let executor = ExternalProver::new("local-execution", "r0vm");
    println!("r0vm_version=3.0.3");
    println!("native_program_id=0x{}", compute_image_id(&elf)?);
    let session = executor
        .execute(execution_env(&input)?, &elf)
        .context("RISC Zero execution")?;
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "guest did not halt successfully"
    );
    ensure!(
        session.journal.bytes == expected,
        "RISC Zero/native V2 journal mismatch"
    );
    let parsed = automata_dcap_zkvm::parse_output_v2(&session.journal.bytes)
        .context("SDK V2 journal decoding")?;
    println!(
        "user_cycles={} journal_bytes={} parity=PASS",
        session.cycles(),
        session.journal.bytes.len()
    );
    println!(
        "quote_version={} output_format={}.{} piid_present={}",
        parsed.quote_version,
        parsed.format_major_version,
        parsed.format_minor_version,
        parsed.piid_present
    );

    if args.len() == 3 {
        for (name, invalid) in negative_cases::negative_inputs(&input)? {
            ensure!(
                dcap_rs::v2::verify_guest_input_v2(&invalid).is_err(),
                "native V2 unexpectedly accepted {name}"
            );
            let result = executor.execute(execution_env(&invalid)?, &elf);
            let error = result.expect_err("RISC Zero V2 unexpectedly accepted invalid input");
            // The pinned r0vm reports guest aborts through this error message.
            // Do not count cycle limits, transport errors or arbitrary faults as rejection.
            let cause = error.root_cause().to_string();
            ensure!(
                cause.starts_with("Guest panicked:") && cause.contains("DCAP V2 verification:"),
                "unexpected RISC Zero failure for {name}: {error:#}"
            );
            println!("rejection={name} native_and_guest=PASS");
        }
    }
    println!("Execution only: no proof generated or universal verifier checked.");
    Ok(())
}
