use anyhow::{Context, Result};
use sp1_sdk::{network::FulfillmentStrategy, NetworkProver, SP1ProvingKey, SP1Stdin};

use super::config::{NetworkProverMode, ProofSystem};

/// Prove using SP1 network prover
pub async fn prove(
    client: &NetworkProver,
    pk: &SP1ProvingKey,
    stdin: &SP1Stdin,
    proof_system: ProofSystem,
    network_mode: NetworkProverMode,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Map network mode to fulfillment strategy
    let strategy = match network_mode {
        NetworkProverMode::Hosted => FulfillmentStrategy::Hosted,
        NetworkProverMode::Reserved => FulfillmentStrategy::Reserved,
        NetworkProverMode::Auction => FulfillmentStrategy::Auction,
    };

    println!("Proof system: {:?}", proof_system);
    println!("Fulfillment strategy: {:?}", strategy);

    // Generate the proof using builder pattern
    let proof = match proof_system {
        ProofSystem::Groth16 => {
            client
                .prove(pk, stdin)
                .groth16()
                .strategy(strategy)
                .await
                .context("SP1 Groth16 proving failed")?
        }
        ProofSystem::Plonk => {
            client
                .prove(pk, stdin)
                .plonk()
                .strategy(strategy)
                .await
                .context("SP1 Plonk proving failed")?
        }
    };

    let journal = proof.public_values.to_vec();
    let proof_bytes = proof.bytes();

    Ok((journal, proof_bytes))
}
