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
use hex;

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
    // Example: These would typically come from your zkVM execution
    // For RiscZero, output_bytes contains the verified attestation data
    let output_bytes: &[u8] = &hex::decode("02550004000000810790c06f000000040102000000000000000000000000009790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000080e702060000000000f2dd2696f69b950645832bdc095ffd11247eeff687eeacdb57a58d2ddb9a9f94fea40c961e19460c00ffa31420ecbc180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000998204508d58dcbfebe5e11c48669f7a921ac2da744dfb7d014ecdff2acdff1c9f665fdad52aadacf296a1df9909eb2383d100224f1716aeb431f7cb3cf028197dbd872487f27b0f6329ab17647dc9953c7014109818634f879e6550bc60f93eecfc42ff4d49278bfdbb0c77e570f4490cff10a2ee1ac11fbd2c2b49fa6cfa3cf1a1cb755c72522dd8a689e9d47906a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000278e753482976c8a7351fe2113609c7350d491cdae3d449eefc202fa41b2ad6840239cc2ba084c2d594b4e6dabeae0fcbf71c96daf0d0c9ecf0e9810c04579000000000067a1dbde26bfe4de343d160db8c6e91dfa058e2669f130a165acdf3d29ddbcead7ae195e472509cb7f6530561a16654d93b5c51206af4a6a874d59f8da5d5f93e25496040fa74a3f32c80b978c8ad671395dabf24283eef9091bc3919fd39b9915a87f1adf3061c165c0191e2658256a2855cac9267f179aafb1990c9e918d6452816adf9953f245d005b9d7d8e36a842a60b51e5cf85b2c2072ae397c178535c9985b77ddda10bf8d35a769eecc37227eccfc994fe037229a6eef201cf84a14cbf472b9").unwrap();
    
    // Example: This would be the Groth16 proof from your zkVM
    // For RiscZero, this is the cryptographic proof that validates the output
    let proof_bytes: &[u8] = &hex::decode("1850aa52559f1d4a858a48b788b52bdd963888e29465a59ca4dace241ad1aeef2b1796d0acb6ea9f4d77a60a0555f28c85867e62b91ac8d0473ff017c88883da077c6be0d1140a77f0ab695679470472cc32f55ebdcf735e9d52ff4a53d3b685020772e77e8e94578796fd6cc122420a77c1c0ba8dff1c6e07e53e30da46d483147732f37ffb72fda399256a551beb49da688ea7cbdcf268fbc15695c3db42a40569e5093c75654a1390cb1fe9c57c360a8f338f66d61ae1115d4584faecc36f238a9eb4cfecea8d3e4995a354dbe5c4bc12db6a12da41e376931548110fb3c008c01d08cf9e8afb7fe661befbb5afce139c9a1ba1b6c10562645ce60954ab48").unwrap();

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
