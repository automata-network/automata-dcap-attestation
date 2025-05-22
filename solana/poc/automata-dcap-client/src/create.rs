use anyhow::Result;
use borsh::BorshSerialize;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program, sysvar
};

use crate::{derive_output_account, get_current_count, DCAP_COUNTER_PUBKEY, DCAP_PROGRAM_ID};

pub fn create_output_account_instruction(
    rpc_client: &RpcClient,
    from: &Pubkey,
    verified_output: &[u8],
) -> Result<Instruction> {
    let current_count = get_current_count(rpc_client)?;
    let (pda_derived, _) = derive_output_account(current_count);

    let mut instruction_data: Vec<u8> = vec![];
    (from, verified_output).serialize(&mut instruction_data)?;
    instruction_data = [vec![0], instruction_data].concat();

    Ok(Instruction::new_with_bytes(
        DCAP_PROGRAM_ID,
        &instruction_data,
        vec![
            AccountMeta::new(from.clone(), true),
            AccountMeta::new(DCAP_COUNTER_PUBKEY, false),
            AccountMeta::new(pda_derived, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
        ],
    ))
}
