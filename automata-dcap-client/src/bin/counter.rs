use anyhow::Result;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    rent::Rent, signer::{keypair::Keypair, Signer}, system_instruction::create_account, sysvar::Sysvar, transaction::Transaction
};
use std::{env, fs, path::PathBuf};

use automata_dcap_client::{DCAP_COUNTER_PUBKEY, DCAP_PROGRAM_ID};

fn main() -> Result<()> {
    // instantiate RPC client
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    println!("RPC URL: {}", rpc_url.as_str());
    let client = RpcClient::new(rpc_url);

    // instantiate payer
    let payer = load_payer()?;
    let payer_pubkey = payer.pubkey();
    println!("Payer address: {}", payer_pubkey.to_string());

    let space = 8usize;
    let rent_exempt_lamports = match Rent::get() {
        Ok(rent) => rent.minimum_balance(space),
        Err(_) => {
            let rent = Rent::default();
            rent.minimum_balance(space)
        }
    };

    // load counter keypair
    let counter_keypair = load_counter_keypair()?;

    let create_account_instruction = create_account(
        &payer_pubkey,
        &DCAP_COUNTER_PUBKEY,
        rent_exempt_lamports,
        space as u64,
        &DCAP_PROGRAM_ID,
    );

    let mut tx = Transaction::new_with_payer(&[create_account_instruction], Some(&payer_pubkey));
    tx.sign(&[&payer, &counter_keypair], client.get_latest_blockhash()?);
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Counter account created, tx sig: {}", sig.to_string());

    Ok(())
}

fn load_payer() -> Result<Keypair> {
    // Warning: home_dir() is not correct for Windows OS
    let mut keypair_dir = env::home_dir().unwrap();

    keypair_dir.push(".config");
    keypair_dir.push("solana");
    keypair_dir.push("id.json");

    let keypair_read = fs::read_to_string(keypair_dir)?;
    let keypair_vec: Vec<u8> = serde_json::from_str(keypair_read.as_str())?;

    Ok(Keypair::from_bytes(&keypair_vec)?)
}

fn load_counter_keypair() -> Result<Keypair> {
    let keypair_dir = PathBuf::from(format!(
        "{}/../automata-dcap-program/keypair/{}.json",
        env::var("CARGO_MANIFEST_DIR").expect("Invalid cargo manifest env value"),
        DCAP_COUNTER_PUBKEY.to_string()
    ));

    let keypair_read = fs::read_to_string(keypair_dir)?;
    let keypair_vec: Vec<u8> = serde_json::from_str(keypair_read.as_str())?;

    Ok(Keypair::from_bytes(&keypair_vec)?)
}
