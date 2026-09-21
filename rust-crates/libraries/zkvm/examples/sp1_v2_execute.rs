//! Local SP1 V2 execution, native journal parity and optional rejection checks.
//! This does not generate proofs, contact a prover network or register a program.
#[path = "../../dcap-rs/tests/support/v2_negative_cases.rs"]
mod negative_cases;
use anyhow::{ensure, Context, Result};
use sp1_sdk::{Elf, HashableKey, LightProver, Prover, ProvingKey, SP1Stdin, SP1_CIRCUIT_VERSION};

const EXECUTION_CYCLE_LIMIT: u64 = 500_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        (2..=4).contains(&args.len())
            && args[2..]
                .iter()
                .all(|a| a == "--negative" || a == "--minimal" || a == "--expect-reject"),
        "usage: sp1_v2_execute <ELF> <V2 ABI input> [--negative] [--minimal] [--expect-reject]"
    );
    let expect_reject = args.iter().any(|a| a == "--expect-reject");
    ensure!(
        !(expect_reject && args.iter().any(|a| a == "--negative")),
        "--expect-reject checks the primary input itself and cannot combine with --negative"
    );
    let elf = std::fs::read(&args[0]).context("read ELF")?;
    let input = std::fs::read(&args[1]).context("read V2 ABI input")?;
    automata_dcap_zkvm::sp1::prover::validate_v6_elf(&elf)?;
    let elf = Elf::from(elf);
    let minimal = args.iter().any(|a| a == "--minimal");
    let verify = if minimal {
        dcap_rs::v2::verify_guest_input_v2_minimal
    } else {
        dcap_rs::v2::verify_guest_input_v2
    };
    let minimal_label = if minimal {
        "DCAP V2 minimal verification:"
    } else {
        "DCAP V2 verification:"
    };
    // Mode-divergent policy fixtures (e.g. the Alibaba migration-service quote)
    // must be rejected natively in this mode and rejected by the guest as well.
    if expect_reject {
        let rejection = verify(&input).expect_err("native V2 unexpectedly accepted policy input");
        println!("mode={}", if minimal { "minimal" } else { "strict" });
        println!("native_rejection={rejection}");
        std::env::set_var("SP1_DISABLE_PROGRAM_CACHE", "true");
        for name in ["VERIFY_VK", "FIX_CORE_SHAPES", "FIX_RECURSION_SHAPES"] {
            ensure!(
                std::env::var(name).map_or(true, |value| value.eq_ignore_ascii_case("true")),
                "execution checks require the default {name}=true setting"
            );
        }
        let client = LightProver::new().await;
        let pk = client.setup(elf.clone()).await?;
        let vk = pk.verifying_key();
        println!("circuit_version={}", SP1_CIRCUIT_VERSION.trim());
        println!("native_program_id={}", vk.bytes32());
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (stderr_tx, stderr_rx) = tokio::sync::watch::channel(String::new());
        let (_, report) = client
            .execute(elf.clone(), stdin)
            .cycle_limit(EXECUTION_CYCLE_LIMIT)
            .stderr(stderr_tx)
            .await
            .context("policy guest execution transport")?;
        let stderr = stderr_rx.borrow();
        ensure!(
            report.exit_code == 1 && stderr.contains(minimal_label),
            "unexpected SP1 policy rejection: exit={} stderr={}",
            report.exit_code,
            stderr.as_str()
        );
        println!("policy_rejection=native_and_guest=PASS");
        println!("Execution only: no proof generated or universal verifier checked.");
        return Ok(());
    }
    let expected = verify(&input).context("native V2 verification")?;
    println!("mode={}", if minimal { "minimal" } else { "strict" });

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
    let client = LightProver::new().await;
    let pk = client.setup(elf.clone()).await?;
    let vk = pk.verifying_key();
    println!("circuit_version={}", SP1_CIRCUIT_VERSION.trim());
    println!("native_program_id={}", vk.bytes32());
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (journal, report) = client
        .execute(elf.clone(), stdin)
        .cycle_limit(EXECUTION_CYCLE_LIMIT)
        .await
        .context("SP1 execution")?;
    ensure!(report.exit_code == 0, "SP1 guest failed");
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

    if args.iter().any(|a| a == "--negative") {
        for (name, invalid) in negative_cases::negative_inputs(&input)? {
            ensure!(
                verify(&invalid).is_err(),
                "native V2 unexpectedly accepted {name}"
            );
            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&invalid);
            let (stderr_tx, stderr_rx) = tokio::sync::watch::channel(String::new());
            let (_, report) = client
                .execute(elf.clone(), stdin)
                .cycle_limit(EXECUTION_CYCLE_LIMIT)
                .stderr(stderr_tx)
                .await
                .context("negative guest execution transport")?;
            // v6 reports guest failure in ExecutionReport, not a host Err. Require
            // both the intended validation panic and exit status; faults are not passes.
            let stderr = stderr_rx.borrow();
            ensure!(
                report.exit_code == 1 && stderr.contains(minimal_label),
                "unexpected SP1 rejection for {name}: exit={} stderr={}",
                report.exit_code, stderr.as_str()
            );
            println!("rejection={name} native_and_guest=PASS");
        }
    }
    println!("Execution only: no proof generated or universal verifier checked.");
    Ok(())
}
