use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program
};

use crate::{derive_output_account, DCAP_PROGRAM_ID};

pub fn delete_output_account_instruction(from: &Pubkey, index: u64) -> Instruction {
    let index_serialized = u64::to_le_bytes(index);
    let instruction_data: Vec<u8> = [vec![2], index_serialized.to_vec()].concat();
    let (output_pubkey, _) = derive_output_account(index);

    Instruction::new_with_bytes(
        DCAP_PROGRAM_ID,
        &instruction_data,
        vec![
            AccountMeta::new(from.clone(), true),
            AccountMeta::new(output_pubkey, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
    )
}