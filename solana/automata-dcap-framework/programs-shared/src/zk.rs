use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};
use anyhow::Result;

// zkVM Verifier Program Constants
// TODO
pub const SP1_DCAP_P256_VERIFIER_ADDR: Pubkey = Pubkey::from_str_const("DGutdUnF1aksBDqqqwUDxnRHCURXDigVEoCPZGZgiWsM");

// Program Identifier constans
pub const ECDSA_SP1_DCAP_P256_VKEY: [u8; 32] = [
    0, 111, 202, 109, 191, 166, 239, 42, 224, 146, 249, 26, 3, 212, 159, 255, 220, 251, 19, 62, 72,
    240, 105, 251, 148, 90, 95, 152, 48, 11, 41, 149,
];

#[derive(Debug, Clone, Copy, AnchorSerialize, AnchorDeserialize)]
#[repr(u64)]
pub enum ZkvmSelector {
    Invalid = 0,
    RiscZero = 1,
    Succinct = 2,
}

impl ZkvmSelector {
    pub fn to_u64(&self) -> u64 {
        *self as u64
    }

    pub fn from_u64(value: u64) -> Self {
        match value {
            1 => ZkvmSelector::RiscZero,
            2 => ZkvmSelector::Succinct,
            _ => ZkvmSelector::Invalid,
        }
    }

    pub fn get_ecdsa_program_vkey(&self) -> Option<&'static [u8; 32]> {
        match self {
            ZkvmSelector::Succinct => Some(&ECDSA_SP1_DCAP_P256_VKEY),
            _ => None,
        }
    }
}

pub fn compute_output_digest(
    fingerprint: &[u8],
    subject_tbs_digest: &[u8],
    issuer_tbs_digest: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(fingerprint);
    hasher.update(subject_tbs_digest);
    hasher.update(issuer_tbs_digest);
    let result: [u8; 32] = hasher.finalize().try_into().unwrap();
    result
}

pub fn digest_ecdsa_zk_verify<'a>(
    output_digest: [u8; 32],
    proof: &[u8],
    zkvm_selector: ZkvmSelector,
    zkvm_verifier_account_info: &AccountInfo<'a>
) -> Result<Vec<u8>> {
    let ecdsa_program_vkey = zkvm_selector.get_ecdsa_program_vkey().unwrap();
        
    // // First, we get the instruction data and the zkvm verifier address
    // let (zk_verify_instruction_data, zkvm_verifier_address) = match zkvm_selector {
    //     ZkvmSelector::RiscZero => (
    //         risc0_verify_instruction_data(
    //             proof,
    //             *ecdsa_program_vkey,
    //             output_digest
    //         ),
    //         RISC0_VERIFIER_ROUTER_ID,
    //     ),
    //     _ => {
    //         return Err(PccsError::UnsupportedZkvm.into());
    //     },
    // };

    // // Check zkvm verifier program
    // // require!(
    // //     zkvm_verifier_program.key == &zkvm_verifier_address,
    // //     DcapVerifierError::InvalidZkvmProgram
    // // );

    // // Create the context for the CPI call
    // let verify_cpi_context = CpiContext::new(
    //     zkvm_verifier_account_info.clone(),
    //     vec![system_program.to_account_info()],
    // );

    // // Invoke CPI to the zkvm verifier program
    // invoke(
    //     &Instruction {
    //         program_id: zkvm_verifier_account_info.key(),
    //         accounts: verify_cpi_context.to_account_metas(None),
    //         data: zk_verify_instruction_data
    //     },
    //     &[system_program.to_account_info()]
    // ).unwrap();

    Ok(vec![]) // TODO
}