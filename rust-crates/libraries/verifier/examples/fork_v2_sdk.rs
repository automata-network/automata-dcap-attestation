//! SDK/native parity and optional signed transactions on a local Anvil fork.
use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::BlockNumberOrTag,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolType,
};
use anyhow::{Context, Result, ensure};
use automata_dcap_evm_bindings::v2::{
    IAutomataDcapAttestationV2, IAutomataDcapAttestationV2Default,
};
use automata_dcap_verifier::verify_and_attest_on_chain_v2;
use std::path::Path;
mod fork_support;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2 || args.len() == 3,
        "usage: fork_v2_sdk ANVIL_DEPLOYMENT_REPORT FIXTURE_DIRECTORY [NEW_TRANSACTION_REPORT]"
    );
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
    let transaction_report = args.get(2).map(Path::new);
    if let Some(file) = transaction_report {
        ensure!(!file.exists(), "transaction report already exists");
    }
    // An ephemeral test wallet only. No environment/operator key is loaded.
    let signer = PrivateKeySigner::random();
    let account = signer.address();
    let signed_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(endpoint.parse()?);
    if transaction_report.is_some() {
        let _: serde_json::Value = provider
            .raw_request("anvil_setBalance".into(), (account, "0x56bc75e2d63100000"))
            .await?;
    }
    let mut rows = Vec::new();
    let address: Address = report["contracts"]["AutomataDcapAttestationV2"]["address"]
        .as_str()
        .context("FeeV2 address missing")?
        .parse()?;
    for name in ["ata-sgx-v3", "ata-tdx-v4", "v5"] {
        let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
            Path::new(&args[1]).join(format!("{name}.json")),
        )?)?;
        let input = hex::decode(
            fixture["guestInput"]
                .as_str()
                .context("guestInput missing")?
                .trim_start_matches("0x"),
        )?;
        type Input = sol!((bytes, bytes, uint64));
        let (collateral, quote, _) = Input::abi_decode_params(&input)?;
        let eval = fixture["tcbEvaluationDataNumber"]
            .as_u64()
            .context("evaluation missing")? as u32;
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .context("block missing")?;
        let timestamp = block.header.timestamp;
        let input = Input::abi_encode_params(&(collateral.clone(), quote.clone(), timestamp));
        let native =
            dcap_rs::v2::verify_guest_input_v2(&input).context("native full DCAP verification")?;
        let output = verify_and_attest_on_chain_v2(&provider, address, &quote, eval, false).await?;
        ensure!(
            output.output.as_ref() == native,
            "{name}: native vs explicit SDK output mismatch"
        );
        let minimal = verify_and_attest_on_chain_v2(&provider, address, &quote, eval, true).await?;
        ensure!(
            minimal.output == output.output && minimal.quote_body == output.quote_body,
            "{name}: minimal SDK output mismatch"
        );
        let result = IAutomataDcapAttestationV2Default::new(address, &provider)
            .verifyAndAttestOnChainV2(Bytes::copy_from_slice(&quote))
            .call()
            .await?;
        ensure!(
            result.success && result.output.as_ref() == native,
            "{name}: default selector mismatch"
        );
        let mut changed = quote.to_vec();
        changed[80] ^= 1;
        ensure!(
            verify_and_attest_on_chain_v2(&provider, address, &changed, eval, false)
                .await
                .is_err(),
            "modified quote accepted"
        );
        let mut padded = quote.to_vec();
        padded.push(0);
        ensure!(
            verify_and_attest_on_chain_v2(&provider, address, &padded, eval, false)
                .await
                .is_err(),
            "padded quote accepted"
        );
        ensure!(
            verify_and_attest_on_chain_v2(&provider, address, &quote, u32::MAX, false)
                .await
                .is_err(),
            "invalid evaluation accepted"
        );
        let after = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .context("block missing")?;
        ensure!(
            after.header.hash == block.header.hash,
            "fork changed during parity test; rerun without concurrent writers"
        );
        println!(
            "{name}: native verification / explicit SDK / default binding / three negatives PASS; timestamp={timestamp} journal_bytes={}",
            native.len()
        );
        if transaction_report.is_some() {
            // Both public transaction overloads are exercised through SDK bindings.
            for automatic in [false, true] {
                let payment = U256::from(100_000_000_000_000_000u64);
                let receipt = if automatic {
                    IAutomataDcapAttestationV2Default::new(address, &signed_provider)
                        .verifyAndAttestOnChainV2(quote.clone())
                        .value(payment)
                        .send()
                        .await?
                        .get_receipt()
                        .await?
                } else {
                    IAutomataDcapAttestationV2::new(address, &signed_provider)
                        .verifyAndAttestOnChainV2(quote.clone(), eval, false)
                        .value(payment)
                        .send()
                        .await?
                        .get_receipt()
                        .await?
                };
                ensure!(receipt.status(), "raw SDK transaction reverted");
                let block = provider
                    .get_block_by_hash(receipt.block_hash.context("receipt block missing")?)
                    .await?
                    .context("receipt block not found")?;
                let input = Input::abi_encode_params(&(
                    collateral.clone(),
                    quote.clone(),
                    block.header.timestamp,
                ));
                let expected = dcap_rs::v2::verify_guest_input_v2(&input)?;
                let mut found = 0;
                for log in receipt
                    .inner
                    .logs()
                    .iter()
                    .filter(|log| log.address() == address)
                {
                    let event = log
                        .log_decode_validate::<IAutomataDcapAttestationV2::AttestationSubmittedV2>(
                        )?;
                    let event = &event.inner.data;
                    ensure!(
                        event.success
                            && event.verifierType == 0
                            && event.formatMajorVersion == 2
                            && event.formatMinorVersion == 1
                            && event.output.as_ref() == expected,
                        "raw SDK event/output mismatch"
                    );
                    found += 1;
                }
                ensure!(found == 1, "expected exactly one V2 event");
                println!(
                    "{name}: SDK signed transaction default={automatic} PASS gas={} tx={}",
                    receipt.gas_used, receipt.transaction_hash
                );
                rows.push(serde_json::json!({"fixture": name, "automatic": automatic,
                    "transactionHash": receipt.transaction_hash, "gasUsed": receipt.gas_used,
                    "timestamp": block.header.timestamp, "receipt": receipt}));
            }
        }
    }
    if let Some(file) = transaction_report {
        use std::io::Write;
        std::fs::OpenOptions::new().write(true).create_new(true).open(file)?
            .write_all(&serde_json::to_vec_pretty(&serde_json::json!({"sdk": "rust", "status": "PASS",
                "scope": "raw explicit/default calls and signed transactions, three negatives, native/output/event parity",
                "results": rows}))?)?;
    }
    Ok(())
}
