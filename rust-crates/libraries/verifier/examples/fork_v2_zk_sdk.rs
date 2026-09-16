//! Real-proof SDK acceptance on the exact local Sepolia fork. Never broadcasts publicly.
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result, ensure};
use automata_dcap_evm_bindings::v2::{
    IAutomataDcapAttestationV2, IAutomataDcapAttestationV2Default,
};
use automata_dcap_verifier::{ZkCoprocessor, verify_and_attest_with_zk_proof_v2};
use std::{io::Write, path::Path};
mod fork_support;

sol! {
    #[sol(rpc)]
    interface ForkPauseAdmin {
        function zkV2Paused() external view returns (bool);
        function setZkV2Paused(bool paused) external;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: fork_v2_zk_sdk ANVIL_REPORT VERIFIED_EVM_PROOF NEW_TX_REPORT"
    );
    ensure!(!Path::new(&args[2]).exists(), "output already exists");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    let proof: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    ensure!(
        report["status"] == "DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS"
            && proof["localVerification"] == "PASS",
        "verified inputs required"
    );
    let endpoint = report["rpc"].as_str().context("RPC missing")?;
    let port: u16 = endpoint
        .strip_prefix("http://127.0.0.1:")
        .context("loopback Anvil only")?
        .parse()?;
    ensure!(port != 0, "invalid local port");
    let provider = ProviderBuilder::new().connect_http(endpoint.parse()?);
    let info: serde_json::Value = provider.raw_request("anvil_nodeInfo".into(), ()).await?;
    fork_support::validate_origin(&report, &info)?;
    let address: Address = report["contracts"]["AutomataDcapAttestationFeeV2"]["address"]
        .as_str()
        .context("Fee missing")?
        .parse()?;
    let owner: Address = report["owner"].as_str().context("owner missing")?.parse()?;
    let backend = proof["backend"].as_u64().context("backend missing")?;
    ensure!(
        backend == 1 || backend == 2,
        "production proof backend only"
    );
    let backend = backend as u8;
    let kind = ZkCoprocessor::try_from(backend)?;
    let id: B256 = proof["programId"]
        .as_str()
        .context("program ID missing")?
        .parse()?;
    let journal: Bytes = proof["journal"]
        .as_str()
        .context("journal missing")?
        .parse()?;
    let seal: Bytes = proof["proof"].as_str().context("proof missing")?.parse()?;
    ensure!(journal.len() > 25 && seal.len() > 4, "invalid framing");
    // This acceptance fixture uses evaluation 20. Other evaluations need their own manifest.
    const EVAL: u32 = 20;
    let signer = PrivateKeySigner::random();
    let account = signer.address();
    let signed = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(endpoint.parse()?);
    let _: serde_json::Value = provider
        .raw_request("anvil_setBalance".into(), (account, "0x56bc75e2d63100000"))
        .await?;
    let admin = ForkPauseAdmin::new(address, &provider);
    let original_pause = admin.zkV2Paused().call().await?;
    if original_pause {
        ensure!(
            verify_and_attest_with_zk_proof_v2(
                &provider,
                address,
                &journal,
                kind,
                &seal,
                Some(id),
                EVAL,
                false
            )
            .await
            .is_err(),
            "paused V2 accepted"
        );
    }
    let _: serde_json::Value = provider
        .raw_request("anvil_impersonateAccount".into(), (owner,))
        .await?;
    // Capture failures so pause restoration and impersonation cleanup also run on a failed check.
    let checks: Result<Vec<serde_json::Value>> = async {
        ensure!(admin.setZkV2Paused(false).from(owner).send().await?.get_receipt().await?.status(), "unpause failed");
        for selected in [Some(id), None] {
            for min_check in [false, true] {
                let got = verify_and_attest_with_zk_proof_v2(&provider, address, &journal, kind, &seal, selected, EVAL, min_check).await?;
                ensure!(got == journal, "SDK journal mismatch");
            }
        }
        let got = IAutomataDcapAttestationV2Default::new(address, &provider)
            .verifyAndAttestWithZKProofV2(journal.clone(), backend, seal.clone()).call().await?;
        ensure!(got.success && got.output == journal, "default binding mismatch");
        let mut changed_seal = seal.to_vec();
        let last = changed_seal.len() - 1;
        changed_seal[last] ^= 1;
        let mut changed_journal = journal.to_vec();
        changed_journal[25] ^= 1;
        let mut wrong_id = id;
        wrong_id[31] ^= 1;
        for (j, p, i) in [(&journal[..], &changed_seal[..], id), (&changed_journal[..], &seal[..], id), (&journal[..], &seal[..], wrong_id)] {
            ensure!(verify_and_attest_with_zk_proof_v2(&provider, address, j, kind, p, Some(i), EVAL, false).await.is_err(), "proof/journal/ID negative accepted");
        }
        let mut rows = Vec::new();
        for automatic in [false, true] {
            let payment = U256::from(100_000_000_000_000_000u64);
            let receipt = if automatic {
                IAutomataDcapAttestationV2Default::new(address, &signed)
                    .verifyAndAttestWithZKProofV2(journal.clone(), backend, seal.clone())
                    .value(payment).send().await?.get_receipt().await?
            } else {
                IAutomataDcapAttestationV2::new(address, &signed)
                    .verifyAndAttestWithZKProofV2(journal.clone(), backend, seal.clone(), id, EVAL, false)
                    .value(payment).send().await?.get_receipt().await?
            };
            ensure!(receipt.status(), "ZK transaction reverted");
            let mut found = 0;
            for log in receipt.inner.logs().iter().filter(|log| log.address() == address) {
                let event = log.log_decode_validate::<IAutomataDcapAttestationV2::AttestationSubmittedV2>()?;
                let event = &event.inner.data;
                ensure!(event.success && event.verifierType == backend && event.formatMajorVersion == 2 && event.formatMinorVersion == 1 && event.output == journal, "ZK V2 event mismatch");
                found += 1;
            }
            ensure!(found == 1, "expected one ZK event");
            println!("real ZK default={automatic} PASS gas={} tx={}", receipt.gas_used, receipt.transaction_hash);
            rows.push(serde_json::json!({"backend": backend, "automatic": automatic, "transactionHash": receipt.transaction_hash, "gasUsed": receipt.gas_used, "receipt": receipt}));
        }
        Ok(rows)
    }.await;
    let restored: Result<()> = async {
        ensure!(
            admin
                .setZkV2Paused(original_pause)
                .from(owner)
                .send()
                .await?
                .get_receipt()
                .await?
                .status(),
            "pause restoration failed"
        );
        ensure!(
            admin.zkV2Paused().call().await? == original_pause,
            "pause readback mismatch"
        );
        Ok(())
    }
    .await;
    let cleanup: Result<serde_json::Value, _> = provider
        .raw_request("anvil_stopImpersonatingAccount".into(), (owner,))
        .await;
    restored?;
    cleanup?;
    let rows = checks?;
    std::fs::OpenOptions::new().write(true).create_new(true).open(&args[2])?
        .write_all(&serde_json::to_vec_pretty(&serde_json::json!({"sdk": "rust", "status": "PASS", "scope": "real ZK SDK calls and explicit/default signed binding transactions, exact events, paused/proof/journal/ID negatives, original pause restored", "results": rows}))?)?;
    Ok(())
}
