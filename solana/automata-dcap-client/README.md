# Automata DCAP on Solana Rust Client

Add the line below in your project's `Cargo.toml`.

```toml
[dependencies]
automata-dcap-client = { git = "https://github.com/automata-network/automata-dcap-attestation.git" }
# other dependencies...
```

## Example

```rust
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
    compute_budget::ComputeBudgetInstruction,
};

use automata_dcap_client::{
    get_index_from_create_output_account,
    create::*,
    verify::{self, ZkvmSelector},
    delete::*
};

fn main() -> Result<()> {
    // instantiate the client
    let rpc_url = String::from("https://api.devnet.solana.com");
    let client = RpcClient::new(rpc_url);

    // generate the payer wallet
    let payer = Keypair::generate();
    let payer_pubkey = payer.pubkey();

    // ... implementations that get you `output_bytes` and `proof_bytes`
    let output_bytes: &[u8] = todo!;
    let proof_bytes: &[u8] = todo!;

    // Tx 1: create the output PDA to upload the output
    let create_instruction = create::create_output_account_instruction(
        &client,
        &payer_pubkey,
        output_bytes
    )?;
    let mut tx_1 = Transaction::new_with_payer(&[create_instruction], Some(&payer_pubkey));
    tx_1.sign(&[&payer], client.get_latest_blockhash()?);
    let sig_tx_1 = client.send_and_confirm_transaction(&tx_1)?;

    // Before submitting the proof to verify, we need to fetch the id
    // associated with the output by reading the logs from tx_1.
    let output_id = get_index_from_create_output_account(&client, &sig_tx_1)?;

    // Note: Proof verification is likely to consume compute units higher than the default 200_000 CU limit
    // Therefore, we should include the `SetComputeUnitLimit` instruction to request for higher budget. (This will not increase the transaction fee, unless you include a priority fee or additional signers to the transaction)

    // Tx 2: verify the proof

    let verify_instruction = verify::verify_proof_instruction(
        output_id,
        ZkvmSelector::RiscZero, // assuming you get proofs from RiscZero
        &proof_bytes,
    )?;

    let estimated_compute_units: u32 = 320_000; // may vary
    let set_compute_unit_limit_instruction =
        ComputeBudgetInstruction::set_compute_unit_limit(estimated_compute_units);

    let mut tx_2 = Transaction::new_with_payer(
        &[set_compute_unit_limit_instruction, verify_instruction],
        Some(&payer_pubkey),
    );
    tx_2.sign(&[&payer], client.get_latest_blockhash()?);
    let sig_tx_2 = client.send_and_confirm_transaction(&tx_2)?;

    // once the proof has been successfully verified
    // the payer has the option to close the output account to re-claim SOL paid for rent
    // which effectively "deletes" the output data from the chain

    // Tx 3: close the output account
    let delete_instruction = delete::delete_output_account_instruction(
        &payer_pubkey,
        output_id
    );

    let mut tx_3 = Transaction::new_with_payer(
        &[delete_instruction],
        Some(&payer_pubkey),
    );
    tx_3.sign(&[&payer], client.get_latest_blockhash()?);
    let sig_tx_3 = client.send_and_confirm_transaction(&tx_3)?;

    Ok(())
}
```

More examples can be found at our [`Automata DCAP zkVM Demo`](https://github.com/automata-network/automata-dcap-zkvm-cli/blob/solana/dcap-sp1-cli/src/solana/mod.rs). 