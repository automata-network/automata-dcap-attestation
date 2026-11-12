mod boundless;

pub use boundless::prove_with_boundless;

use anyhow::{Context, Error, Result};
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, InnerReceipt, ProverOpts};

/// Prove using Bonsai remote prover
pub async fn prove_with_bonsai(elf: &[u8], input_bytes: &[u8]) -> Result<Vec<u8>> {
    let elf = elf.to_vec();
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
            .prove_with_opts(env, &elf, &prover_opts)
            .context("Bonsai proving failed")?
            .receipt;

        anyhow::ensure!(
            matches!(receipt.inner, InnerReceipt::Groth16(_)),
            "Expected a real Groth16 receipt"
        );
        receipt
            .verify(compute_image_id(&elf)?)
            .context("Bonsai receipt verification failed")?;
        risc0_ethereum_contracts::encode_seal(&receipt).context("Failed to encode Groth16 seal")
    })
    .await
    .context("Bonsai proving task panicked")?
}
