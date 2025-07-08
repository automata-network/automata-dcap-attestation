pub mod sp1;

use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};
use anyhow::Result;

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

    pub fn get_zkvm_verifier_pubkey(&self) -> Option<Pubkey> {
        match self {
            ZkvmSelector::Succinct => Some(sp1::ECDSA_SP1_DCAP_P256_PUBKEY),
            _ => None,
        }
    }

    pub fn get_ecdsa_program_vkey(&self) -> Option<[u8; 32]> {
        match self {
            ZkvmSelector::Succinct => Some(sp1::ECDSA_SP1_DCAP_P256_VKEY),
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

pub fn concatenate_output(
    fingerprint: &[u8],
    subject_tbs_digest: &[u8],
    issuer_tbs_digest: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(96);
    output.extend_from_slice(fingerprint);
    output.extend_from_slice(subject_tbs_digest);
    output.extend_from_slice(issuer_tbs_digest);
    output
}

pub trait VerifyProof {
    fn verify_p256_proof_instruction(&self) -> Result<Vec<u8>>;
}