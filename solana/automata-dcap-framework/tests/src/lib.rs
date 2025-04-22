#[cfg(test)]
mod verifier;

#[cfg(test)]
mod pccs;

use anchor_client::{
    Client, Program,
    anchor_lang::solana_program,
    solana_sdk::{
        pubkey::Pubkey, signature::Keypair, signer::Signer,
    },
};
use anyhow::Result;
use solana_zk::ID as SOLANA_ZK_PROGRAM_ID;

use std::ops::Deref;

pub const TEST_RISC0_VERIFIER_PUBKEY: Pubkey = Pubkey::from_str_const("5Gxa8YTih2rg3NY5EuWLtpS3Eq5xpS7PKWxspAAni5RS");

pub async fn setup_solana_zk_program<C: Clone + Deref<Target = impl Signer>>(
    anchor_client: &Client<C>,
    signer: &Keypair,
    zkvm_selector: u64,
    zkvm_verifier_program: &Pubkey,
) -> Result<()> {
    let solana_zk_program = anchor_client.program(solana_zk::ID).unwrap();
    let payer_pubkey = signer.pubkey();

    let counter_account_pubkey = get_counter_pubkey();

    initialize_solana_zk(&solana_zk_program, &payer_pubkey, &counter_account_pubkey).await?;

    match zkvm_selector {
        1 => {
            assert!(zkvm_verifier_program == &TEST_RISC0_VERIFIER_PUBKEY);
        },
        _ => panic!("Unsupported zkvm selector"),
    };

    add_zkvm_verifier_to_solana_zk(
        &solana_zk_program,
        &payer_pubkey,
        &counter_account_pubkey,
        zkvm_selector,
        &zkvm_verifier_program,
    )
    .await?;

    Ok(())
}

fn solana_zk_program_data_account() -> Pubkey {
    let (program_data_id, _) = Pubkey::find_program_address(
        &[SOLANA_ZK_PROGRAM_ID.as_ref()],
        &solana_program::bpf_loader_upgradeable::ID,
    );
    program_data_id
}

async fn initialize_solana_zk<C: Clone + Deref<Target = impl Signer>>(
    solana_zk_program: &Program<C>,
    payer_pubkey: &Pubkey,
    counter_account_pubkey: &Pubkey,
) -> Result<()> {
    assert!(solana_zk_program.id() == SOLANA_ZK_PROGRAM_ID);

    // Check if counter account already exists
    let counter_account = solana_zk_program
        .rpc()
        .get_account(counter_account_pubkey)
        .await;

    // Only initialize if the account doesn't exist or has zero data
    let account_not_found = counter_account.is_err();
    if account_not_found {
        solana_zk_program
            .request()
            .accounts(solana_zk::accounts::Initialize {
                payer: *payer_pubkey,
                counter: *counter_account_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(solana_zk::instruction::Initialize {})
            .send()
            .await
            .expect("Failed to initialize Solana ZK program");
    }

    Ok(())
}

async fn add_zkvm_verifier_to_solana_zk<C: Clone + Deref<Target = impl Signer>>(
    solana_zk_program: &Program<C>,
    payer_pubkey: &Pubkey,
    counter_account_pubkey: &Pubkey,
    zkvm_selector: u64,
    zkvm_verifier_program: &Pubkey,
) -> Result<()> {
    assert!(solana_zk_program.id() == SOLANA_ZK_PROGRAM_ID);

    let (zkvm_verifier_config_pda, _) =
        solana_zk_client::derive_zkvm_verifier_pda(zkvm_selector, zkvm_verifier_program);

    let counter = solana_zk_program.account::<solana_zk::state::Counter>(
        *counter_account_pubkey,
    ).await?;

    if counter.count + 1u64 == zkvm_selector {
        solana_zk_program
            .request()
            .accounts(solana_zk::accounts::AddZkvmVerifier {
                owner: *payer_pubkey,
                counter: *counter_account_pubkey,
                zkvm_verifier_account: zkvm_verifier_config_pda,
                program_data: solana_zk_program_data_account(),
                zkvm_verifier_program: *zkvm_verifier_program,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(solana_zk::instruction::AddZkVerifierProgram { zkvm_selector })
            .send()
            .await
            .expect("Failed to add zkvm verifier to Solana ZK program");
    }

    Ok(())
}


fn get_counter_pubkey() -> Pubkey {
    let (counter_account_pubkey, _) =
        Pubkey::find_program_address(&[b"counter".as_ref()], &SOLANA_ZK_PROGRAM_ID);
    counter_account_pubkey
}