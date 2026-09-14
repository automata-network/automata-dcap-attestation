//! Read-only PCCS acquisition -> SDK input -> native V2 verification on the reviewed fork.
use alloy::{
    primitives::keccak256,
    providers::{Provider, ProviderBuilder},
};
use anyhow::{ensure, Context, Result};
use automata_dcap_zkvm::{generate_input, Version};
use dcap_rs::v2::verify_guest_input_v2;
use pccs_reader_rs::{PccsReadStrategy, PccsReader};
use std::{io::Write, path::Path, time::Instant};

#[path = "../../verifier/examples/fork_support/mod.rs"]
mod fork_support;

fn decode(value: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value[key]
            .as_str()
            .context("missing hex field")?
            .trim_start_matches("0x"),
    )?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 3 || args.len() == 4,
        "usage: fork_v2_collateral DEPLOYMENT_REPORT FIXTURE_DIRECTORY NEW_OUTPUT_DIRECTORY [GO_INPUT_DIRECTORY]");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    ensure!(
        report["status"] == "DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS",
        "deployment not ready"
    );
    let endpoint = report["rpc"].as_str().context("missing endpoint")?;
    ensure!(
        endpoint.starts_with("http://127.0.0.1:"),
        "localhost Anvil only"
    );
    let provider = ProviderBuilder::new().connect_http(endpoint.parse()?);
    let info: serde_json::Value = provider.raw_request("anvil_nodeInfo".into(), ()).await?;
    fork_support::validate_origin(&report, &info)?;
    let out = Path::new(&args[2]);
    std::fs::create_dir(out)?;
    let start = provider.get_block_number().await?;
    let mut rows = Vec::new();
    for name in ["ata-sgx-v3", "ata-tdx-v4", "v5"] {
        let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
            Path::new(&args[1]).join(format!("{name}.json")),
        )?)?;
        let quote = decode(&fixture, "quote")?;
        let expected = decode(&fixture, "expectedJournal")?;
        let timestamp = fixture["verificationTimestamp"]
            .as_u64()
            .context("timestamp missing")?;
        let eval = u32::try_from(
            fixture["tcbEvaluationDataNumber"]
                .as_u64()
                .context("evaluation missing")?,
        )?;
        for (strategy_name, strategy) in [
            ("direct", PccsReadStrategy::DirectConcurrent),
            ("multicall-with-fallback", PccsReadStrategy::multicall3()),
        ] {
            // The deployed PCCS is reused from V1.1. This does not register a global V2 deployment.
            let reader = PccsReader::from_provider(&provider, Some(Version::V1_1))
                .await?
                .with_read_strategy(strategy);
            for (mode, evaluation) in [("explicit", Some(eval)), ("default", None)] {
                let started = Instant::now();
                let collaterals = reader
                    .find_missing_collaterals_from_quote(&quote, false, evaluation)
                    .await?;
                let acquisition_ms = started.elapsed().as_secs_f64() * 1000.0;
                let started = Instant::now();
                let input = generate_input(&quote, &collaterals, timestamp, Version::V2_0)?;
                let encoding_us = started.elapsed().as_secs_f64() * 1_000_000.0;
                let started = Instant::now();
                let journal = verify_guest_input_v2(&input)?;
                let verification_us = started.elapsed().as_secs_f64() * 1_000_000.0;
                ensure!(
                    journal == expected,
                    "{name}/{strategy_name}/{mode}: acquired collateral journal mismatch"
                );
                let file = format!("{name}-{strategy_name}-{mode}.bin");
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(out.join(&file))?
                    .write_all(&input)?;
                if let Some(go_dir) = args.get(3) {
                    let go_input =
                        std::fs::read(Path::new(go_dir).join(format!("{name}-{mode}.bin")))?;
                    ensure!(
                        verify_guest_input_v2(&go_input)? == expected,
                        "{name}/{mode}: Go input journal mismatch"
                    );
                }
                println!("PASS {name}/{strategy_name}/{mode}: SDK acquisition -> V2 native journal ({} bytes)", journal.len());
                rows.push(serde_json::json!({"fixture": name, "strategy": strategy_name, "evaluationMode": mode,
                    "verificationTimestamp": timestamp, "inputKeccak256": format!("{:#x}", keccak256(&input)),
                    "acquisitionElapsedMs": acquisition_ms, "encodingElapsedMicros": encoding_us, "nativeVerificationElapsedMicros": verification_us,
                    "journalKeccak256": format!("{:#x}", keccak256(&journal)), "inputFile": file}));
            }
        }
    }
    ensure!(
        provider.get_block_number().await? == start,
        "fork changed during read-only acquisition"
    );
    let result = serde_json::json!({"status": "PASS", "scope": "PCCS SDK acquisition and native journal parity; not new ZK proofs",
        "sdk": "rust", "goInputParityChecked": args.len() == 4, "blockNumber": start, "origin": info, "results": rows});
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("report.json"))?
        .write_all(serde_json::to_string_pretty(&result)?.as_bytes())?;
    Ok(())
}
