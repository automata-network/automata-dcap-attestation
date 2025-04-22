use anchor_lang::prelude::*;
use solana_zk::program::SolanaZk;
use solana_zk::state::ZkvmVerifier;
use solana_zk::cpi::accounts::VerifyZkProof;
use solana_zk_client::{RISC0_VERIFIER_ROUTER_ID, verify::risc0::risc0_verify_instruction_data};

use crate::types::zk::ZkvmSelector;
use crate::errors::PccsError;

pub fn digest_ecdsa_zk_verify<'a>(
    output_digest: [u8; 32],
    proof: &[u8],
    zkvm_selector: ZkvmSelector,
    zkvm_verifier_account_info: &AccountInfo<'a>,
    solana_zk_program: &Program<'a, SolanaZk>,
    verifier_config_account: &Account<'a, ZkvmVerifier>,
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

    // Prepare for CPI
    let verify_cpi_accounts = VerifyZkProof {
        zkvm_verifier_account: verifier_config_account.to_account_info(),
        zkvm_verifier_program: zkvm_verifier_account_info.to_account_info(),
        system_program: system_program.to_account_info(),
    };
    let verify_cpi_ctx = CpiContext::new(
        solana_zk_program.to_account_info(),
        verify_cpi_accounts,
    );

    // Invoke CPI
    solana_zk::cpi::verify_zkvm_proof(
        verify_cpi_ctx,
        zkvm_selector.to_u64(),
        zk_verify_instruction_data,
    )
}