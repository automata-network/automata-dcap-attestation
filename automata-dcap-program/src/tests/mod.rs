mod counter;
mod risc0;
mod sp1;
mod delete;

use solana_program::hash::Hash;
use solana_program_test::{BanksClient, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    system_program, sysvar,
    transaction::Transaction
};

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::state::CounterAccountData;
use crate::{DCAP_COUNTER_ADDR, RISC0_GROTH16_VERIFIER_ADDR, SP1_DCAP_GROTH16_VERIFIER_ADDR};

struct TestEnv {
    pub banks_client: BanksClient,
    pub program_id: Pubkey,
    pub risc0_verifier_program_id: Pubkey,
    pub sp1_dcap_verifier_program_id: Pubkey,
    pub counter_account: Pubkey,
    pub payer_keypair: Keypair,
    pub initial_block_hash: Hash,
}

async fn setup_test() -> TestEnv {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");
    let program_id = Pubkey::from_str_const("DcapE9GZZ2KSu6udeW1pVdmqBAHP9NMBLBrxUUYdw1Qk");

    // instantiate ProgramTest environment and deploy the program
    let mut program_test = ProgramTest::new(
        "automata_dcap_program",
        program_id.clone(),
        None,
    );

    // set max compute units to 500_000 CUs
    program_test.set_compute_max_units(500_000);

    // add the Counter account to the environment
    let space = 8usize;
    let one_sol = 1_000_000_000u64;
    let counter_account = Account::new(one_sol, space, &program_id);
    let counter_account_pubkey = Pubkey::from_str_const(DCAP_COUNTER_ADDR);
    program_test.add_account(counter_account_pubkey.clone(), counter_account.clone());

    // add the zkVM verifier programs to the environment

    // the tests/fixtures/ library contains the .so SBF binary for the
    // RiscZero Groth-16-Verifier compiled from
    // https://github.com/preston4896/risc0-solana/blob/8aac7e4e5bd358c4eec0e79fdd3ec4fc910dbe26/solana-verifier/programs/groth_16_verifier/src/lib.rs#L37-L65
    // SP1 DCAP Verifier Program compiled from
    // https://github.com/automata-network/automata-dcap-zkvm-cli/blob/solana/dcap-sp1-cli/dcap-sp1-solana-program/src/lib.rs
    std::env::set_var("SBF_OUT_DIR", "./src/tests/fixtures");

    let sp1_dcap_verifier_program_id = Pubkey::from_str_const(SP1_DCAP_GROTH16_VERIFIER_ADDR);
    program_test.add_program(
        "dcap_sp1_program",
        sp1_dcap_verifier_program_id.clone(),
        None,
    );

    let risc0_verifier_program_id = Pubkey::from_str_const(RISC0_GROTH16_VERIFIER_ADDR);
    program_test.add_program(
        "groth_16_verifier",
        risc0_verifier_program_id.clone(),
        None,
    );

    // start the test
    let (banks_client, payer_keypair, initial_block_hash) = program_test.start().await;

    TestEnv {
        banks_client,
        program_id,
        risc0_verifier_program_id,
        sp1_dcap_verifier_program_id,
        counter_account: counter_account_pubkey,
        payer_keypair,
        initial_block_hash,
    }
}

fn derive_output_account(env: &TestEnv, index: u64) -> Pubkey {
    let seeds: &[&[u8]] = &[b"automata-dcap", &u64::to_le_bytes(index)];

    let (derived_pda, _) = Pubkey::find_program_address(seeds, &env.program_id);

    derived_pda
}

async fn get_current_count(env: &TestEnv) -> Result<u64> {
    let counter_account = env
        .banks_client
        .get_account(env.counter_account)
        .await
        .unwrap()
        .unwrap();
    let counter_account_data = counter_account.data.clone();
    let counter_account_state =
        CounterAccountData::deserialize(&mut counter_account_data.as_slice()).unwrap();

    Ok(counter_account_state.current_count())
}

async fn store_verified_output(env: &TestEnv, output_data: &[u8]) -> Result<Pubkey> {
    let payer_pubkey = env.payer_keypair.pubkey().clone();
    let program_id = env.program_id.clone();
    let pda_derived = derive_output_account(env, 0);

    let mut instruction_data: Vec<u8> = vec![];
    (payer_pubkey, output_data).serialize(&mut instruction_data)?;
    instruction_data = [vec![0], instruction_data].concat();

    let instruction = Instruction::new_with_bytes(
        program_id,
        &instruction_data,
        vec![
            AccountMeta::new(payer_pubkey, true),
            AccountMeta::new(env.counter_account, false),
            AccountMeta::new(pda_derived, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false)
        ],
    );

    let recent_blockhash = &env.banks_client.get_latest_blockhash().await?;

    let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer_pubkey));
    tx.sign(&[&env.payer_keypair], *recent_blockhash);
    env.banks_client.process_transaction(tx).await?;

    Ok(pda_derived)
}

async fn send_proof_to_verify(env: &TestEnv, output_index: u64, zkvm_selector: u8, proof_bytes: &[u8]) -> Result<()> {
    let payer_pubkey = env.payer_keypair.pubkey().clone();
    let program_id = env.program_id.clone();
    let pda_derived = derive_output_account(env, output_index);

    let mut instruction_data: Vec<u8> = vec![];
    (zkvm_selector, proof_bytes).serialize(&mut instruction_data)?;
    instruction_data = [vec![1], instruction_data].concat();
    
    let verifier_pubkey = match zkvm_selector {
        1 => env.risc0_verifier_program_id,
        2 => env.sp1_dcap_verifier_program_id,
        _ => panic!("unknown zkvm selector")
    };

    let instruction = Instruction::new_with_bytes(
        program_id,
        &instruction_data,
        vec![
            AccountMeta::new(pda_derived, false),
            AccountMeta::new_readonly(verifier_pubkey, false),
            AccountMeta::new_readonly(system_program::ID, false)
        ],
    );

    let recent_blockhash = &env.banks_client.get_latest_blockhash().await?;

    let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer_pubkey));
    tx.sign(&[&env.payer_keypair], *recent_blockhash);
    env.banks_client.process_transaction(tx).await?;

    Ok(())
}
