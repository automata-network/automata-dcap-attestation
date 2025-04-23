use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::invoke
};
use solana_zk_client::{RISC0_VERIFIER_ROUTER_ID, verify::risc0::risc0_verify_instruction_data};

use crate::types::zk::ZkvmSelector;
use crate::errors::PccsError;

pub fn digest_ecdsa_zk_verify<'a>(
    output_digest: [u8; 32],
    proof: &[u8],
    zkvm_selector: ZkvmSelector,
    zkvm_verifier_account_info: &AccountInfo<'a>,
    system_program: &Program<'a, System>,
) -> Result<()> {
    let ecdsa_program_vkey = zkvm_selector.get_ecdsa_program_vkey().unwrap();
        
    // First, we get the instruction data and the zkvm verifier address
    let (zk_verify_instruction_data, zkvm_verifier_address) = match zkvm_selector {
        ZkvmSelector::RiscZero => (
            risc0_verify_instruction_data(
                proof,
                *ecdsa_program_vkey,
                output_digest
            ),
            RISC0_VERIFIER_ROUTER_ID,
        ),
        _ => {
            return Err(PccsError::UnsupportedZkvm.into());
        },
    };

    // Check zkvm verifier program
    // require!(
    //     zkvm_verifier_program.key == &zkvm_verifier_address,
    //     DcapVerifierError::InvalidZkvmProgram
    // );

    // Create the context for the CPI call
    let verify_cpi_context = CpiContext::new(
        zkvm_verifier_account_info.clone(),
        vec![system_program.to_account_info()],
    );

    // Invoke CPI to the zkvm verifier program
    invoke(
        &Instruction {
            program_id: zkvm_verifier_account_info.key(),
            accounts: verify_cpi_context.to_account_metas(None),
            data: zk_verify_instruction_data
        },
        &[system_program.to_account_info()]
    ).unwrap();

    Ok(())
}