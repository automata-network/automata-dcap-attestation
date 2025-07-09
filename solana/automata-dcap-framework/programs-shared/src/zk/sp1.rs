use super::*;

use anchor_lang::InstructionData;
use dcap_ecdsa_sp1::instruction::VerifyP256Proof;

pub use dcap_ecdsa_sp1::SP1Groth16Proof;
pub const ECDSA_SP1_DCAP_P256_PUBKEY: Pubkey = dcap_ecdsa_sp1::ID_CONST;
pub const ECDSA_SP1_DCAP_P256_VKEY: [u8; 32] = [
    0, 111, 202, 109, 191, 166, 239, 42, 224, 146, 249, 26, 3, 212, 159, 255, 220, 251, 19, 62, 72,
    240, 105, 251, 148, 90, 95, 152, 48, 11, 41, 149,
];

impl VerifyProof for SP1Groth16Proof {
    fn verify_p256_proof_instruction(&self) -> Result<Vec<u8>> {
        let verify_p256_proof = VerifyP256Proof {
            groth16_proof: self.clone(),
        };

        let instruction_data = verify_p256_proof.data();
        Ok(instruction_data)
    }
}
