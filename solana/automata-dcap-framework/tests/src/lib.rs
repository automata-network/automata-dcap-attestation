#[cfg(test)]
mod verifier;

#[cfg(test)]
mod pccs;

use anchor_client::{
    Program,
    anchor_lang::solana_program,
    solana_sdk::{pubkey::Pubkey, signer::Signer},
};
use anyhow::Result;
use solana_zk::ID as SOLANA_ZK_PROGRAM_ID;
use std::ops::Deref;

pub async fn setup_solana_zk_program<C: Clone + Deref<Target = impl Signer>>(
    solana_zk_program: &Program<C>,
    payer_pubkey: &Pubkey,
    zkvm_selector: u64,
    zkvm_verifier_program: &Pubkey,
) -> Result<()> {
    initialize_solana_zk(&solana_zk_program, payer_pubkey).await?;

    add_zkvm_verifier_to_solana_zk(
        &solana_zk_program,
        payer_pubkey,
        zkvm_selector,
        zkvm_verifier_program,
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
) -> Result<()> {
    assert!(solana_zk_program.id() == SOLANA_ZK_PROGRAM_ID);

    let (counter_account_pubkey, _) =
        Pubkey::find_program_address(&[b"counter".as_ref()], &SOLANA_ZK_PROGRAM_ID);

    solana_zk_program
        .request()
        .accounts(solana_zk::accounts::Initialize {
            payer: *payer_pubkey,
            counter: counter_account_pubkey,
            system_program: anchor_client::solana_sdk::system_program::ID,
        })
        .args(solana_zk::instruction::Initialize {})
        .send()
        .await
        .expect("Failed to initialize Solana ZK program");

    Ok(())
}

async fn add_zkvm_verifier_to_solana_zk<C: Clone + Deref<Target = impl Signer>>(
    solana_zk_program: &Program<C>,
    payer_pubkey: &Pubkey,
    zkvm_selector: u64,
    zkvm_verifier_program: &Pubkey,
) -> Result<()> {
    assert!(solana_zk_program.id() == SOLANA_ZK_PROGRAM_ID);

    let (counter_account_pubkey, _) =
        Pubkey::find_program_address(&[b"counter".as_ref()], &SOLANA_ZK_PROGRAM_ID);

    let (zkvm_verifier_config_pda, _) =
        solana_zk_client::derive_zkvm_verifier_pda(zkvm_selector, zkvm_verifier_program);

    solana_zk_program
        .request()
        .accounts(solana_zk::accounts::AddZkvmVerifier {
            owner: *payer_pubkey,
            counter: counter_account_pubkey,
            zkvm_verifier_account: zkvm_verifier_config_pda,
            program_data: solana_zk_program_data_account(),
            zkvm_verifier_program: *zkvm_verifier_program,
            system_program: anchor_client::solana_sdk::system_program::ID,
        })
        .args(solana_zk::instruction::AddZkVerifierProgram { zkvm_selector })
        .send()
        .await
        .expect("Failed to add zkvm verifier to Solana ZK program");

    Ok(())
}
