mod boundless;

pub use boundless::prove_with_boundless;

use anyhow::{Context, Result, Error};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts};
use risc0_ethereum_contracts::groth16;

/// Prove using Bonsai remote prover
pub async fn prove_with_bonsai(elf: &'static [u8], input_bytes: &[u8]) -> Result<Vec<u8>> {
    let input_bytes = input_bytes.to_vec();

    // Run the blocking Bonsai operation in a separate thread
    tokio::task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write_slice(&input_bytes)
            .build()
            .context("Failed to build executor environment")?;

        // Obtain the default prover.
        let prover = default_prover();

        // Produce a receipt by proving the specified ELF binary.
        let prover_opts = if std::env::var("BONSAI_API_KEY").is_ok() {
            ProverOpts::groth16()
        } else {
            return Err(Error::msg(
                "Bonsai proving requires BONSAI_API_KEY environment variable to be set",
            ));
        };

        let receipt = prover
            .prove_with_opts(env, elf, &prover_opts)
            .context("Bonsai proving failed")?
            .receipt;

        let seal = if let InnerReceipt::Groth16(ref groth16_receipt) = receipt.inner {
            groth16::encode(groth16_receipt.seal.clone())
                .context("Failed to encode Groth16 seal")?
        } else {
            vec![]
        };

        Ok(seal)
    })
    .await
    .context("Bonsai proving task panicked")?
}

