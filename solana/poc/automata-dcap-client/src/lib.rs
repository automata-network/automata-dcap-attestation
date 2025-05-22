pub mod create;
pub mod delete;
pub mod verify;

use anyhow::{Error, Result};
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{pubkey, pubkey::Pubkey, signature::Signature};
use solana_transaction_status_client_types::UiTransactionEncoding;

pub const DCAP_COUNTER_PUBKEY: Pubkey = pubkey!("DcapH8Bt1y6MQHE1hR2Rp1WEBeWfog2Kh9UxtG8UMaNu");
pub const DCAP_PROGRAM_ID: Pubkey = pubkey!("DcapE9GZZ2KSu6udeW1pVdmqBAHP9NMBLBrxUUYdw1Qk");

// gets the current u64 index from the counter.
pub fn get_current_count(rpc_client: &RpcClient) -> Result<u64> {
    let counter_account_data = rpc_client.get_account_data(&DCAP_COUNTER_PUBKEY)?;
    if counter_account_data.len() != 8 {
        return Err(Error::msg("Invalid u64 count data"));
    }
    let current_count = u64::from_le_bytes(counter_account_data[..8].try_into()?);
    Ok(current_count)
}

// computes the PDA account address and canonical bump seed with the given index number
pub fn derive_output_account(index: u64) -> (Pubkey, u8) {
    let seeds: &[&[u8]] = &[b"automata-dcap", &u64::to_le_bytes(index)];

    Pubkey::find_program_address(seeds, &DCAP_PROGRAM_ID)
}

// parse the account creation transaction to get the index from logs
pub fn get_index_from_create_output_account(
    client: &RpcClient,
    tx_signature: &Signature,
) -> Result<u64> {
    let tx = client.get_transaction(tx_signature, UiTransactionEncoding::Json)?;

    let logs = tx
        .transaction
        .meta
        .unwrap()
        .log_messages
        .expect("Missing logs");

    // TEMP: This is assuming that `CreateOutputAccount` is the ONLY instruction in the transaction
    // We might need to add a magic string that we could use to easily locate and identify the Counter ID logs
    // But then again, Solana runtime doesn't specify the program ID that is emitting the logs...
    // So if there are other instructions calling a different program that emits log with our magic string
    // Then there is no way we can tell where is it coming from... :(
    let index_log = &logs[3];
    let parts: Vec<&str> = index_log.split("ID: ").collect();
    if parts.len() != 2 {
        return Err(Error::msg("Invalid log format"));
    }
    let id_str = parts[1];

    Ok(id_str.parse()?)
}
