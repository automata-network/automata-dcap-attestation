use anyhow::{Error, Result};
use borsh::BorshSerialize;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey,
    pubkey::Pubkey,
    system_program
};

use crate::{derive_output_account, DCAP_PROGRAM_ID};

pub const RISC0_GROTH16_VERIFIER_ADDR: Pubkey =
    pubkey!("5HrF6mJAaSFdAym2xZixowzVifPyyzTuTs3viYKdjy4s");
pub const SP1_DCAP_GROTH16_VERIFIER_ADDR: Pubkey =
    pubkey!("2LUaFQTJ7F96A5x1z5sXfbDPM2asGnrQ2hsE6zVDMhXZ");

#[derive(Debug, Clone, Copy, BorshSerialize)]
#[repr(u8)]
pub enum ZkvmSelector {
    None,
    RiscZero,
    SP1,
}

pub fn verify_proof_instruction(
    index: u64,
    zkvm: ZkvmSelector,
    proof_bytes: &[u8],
) -> Result<Instruction> {
    let (pda_derived, _) = derive_output_account(index);

    let mut instruction_data: Vec<u8> = vec![];
    (zkvm, proof_bytes).serialize(&mut instruction_data)?;
    instruction_data = [vec![1], instruction_data].concat();

    let verifier_pubkey = match zkvm {
        ZkvmSelector::RiscZero => RISC0_GROTH16_VERIFIER_ADDR,
        ZkvmSelector::SP1 => SP1_DCAP_GROTH16_VERIFIER_ADDR,
        _ => {
            return Err(Error::msg("Unknown ZkVM selected"));
        }
    };

    Ok(Instruction::new_with_bytes(
        DCAP_PROGRAM_ID,
        &instruction_data,
        vec![
            AccountMeta::new(pda_derived, false),
            AccountMeta::new_readonly(verifier_pubkey, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
    ))
}
