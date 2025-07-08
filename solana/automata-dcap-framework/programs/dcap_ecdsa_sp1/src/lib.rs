#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use sp1_solana::verify_proof;

declare_id!("3tXQLx1CPpecJcBzHBLnC1fvRhLEpHqvWqDRPyxrKDCe");

pub const ECDSA_SP1_DCAP_P256_VKEY: &str =
    "0x006fca6dbfa6ef2ae092f91a03d49fffdcfb133e48f069fb945a5f98300b2995";

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SP1Groth16Proof {
    pub proof: Vec<u8>,
    pub sp1_public_inputs: Vec<u8>,
}

#[program]
pub mod dcap_ecdsa_sp1 {
    use super::*;

    pub fn verify_p256_proof(_ctx: Context<VerifyProof>, groth16_proof: SP1Groth16Proof) -> Result<()> {
        let vk = sp1_solana::GROTH16_VK_5_0_0_BYTES;

        let verified = verify_proof(
            &groth16_proof.proof,
            &groth16_proof.sp1_public_inputs,
            &ECDSA_SP1_DCAP_P256_VKEY,
            vk,
        );

        if verified.is_err() {
            msg!("Proof verification failed");
            return Err(ProgramError::InvalidArgument.into());
        }

        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifyProof {}
