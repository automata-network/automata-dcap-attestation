use anyhow::{ensure, Result};

// Test-only reviewed origins, not arbitrary deployment/default selection.
pub fn validate_origin(report: &serde_json::Value, actual: &serde_json::Value) -> Result<()> {
    let origin = &report["origin"];
    let (chain, block, hash, hardfork) = match origin["environment"]["chainId"].as_u64() {
        Some(11155111) => {
            ensure!(
                (origin["network"].is_null() || origin["network"] == "ethereum")
                    && (actual["network"].is_null() || actual["network"] == "ethereum"),
                "Ethereum runtime required"
            );
            (
                11155111,
                11689923,
                "0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096",
                "Osaka",
            )
        }
        Some(560048) => {
            ensure!(
                (origin["network"].is_null() || origin["network"] == "ethereum")
                    && (actual["network"].is_null() || actual["network"] == "ethereum"),
                "Ethereum runtime required"
            );
            (
                560048,
                3666000,
                "0x507bec8bb301dc25d57e09fee024cf8a099db7e8ee318c483591fed3b738a57f",
                "Osaka",
            )
        }
        Some(11155420) => {
            ensure!(
                origin["network"] == "optimism" && actual["network"] == "optimism",
                "Optimism runtime required"
            );
            (
                11155420,
                48718178,
                "0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c",
                "Karst",
            )
        }
        _ => anyhow::bail!("unreviewed fork chain"),
    };
    ensure!(
        origin["forkConfig"]["forkBlockNumber"] == block
            && origin["currentBlockHash"] == hash
            && origin["hardFork"] == hardfork,
        "deployment fork pin mismatch"
    );
    ensure!(
        actual["environment"]["chainId"] == chain
            && actual["forkConfig"]["forkBlockNumber"] == block
            && actual["hardFork"] == hardfork,
        "runtime fork origin mismatch"
    );
    Ok(())
}
