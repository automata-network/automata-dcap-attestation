use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};
use sp1_solana::verify_proof_raw;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SP1Groth16Proof {
    pub proof: Vec<u8>,
    /// SHA256 of the public inputs
    pub sp1_public_inputs_hash: Vec<u8>,
}

pub const DCAP_VKEY_HASH: &str =
    "0x004be684aaf90b70fb2d8f586ec96c36cee5f6533850b14e8b5568f4dbf31f8e";

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Deserialize the SP1Groth16Proof from the instruction data.
    let mut groth16_proof = SP1Groth16Proof::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Get the SP1 Groth16 verification key from the `sp1-solana` crate.
    let sp1_verifier_vk = sp1_solana::GROTH16_VK_4_0_0_RC3_BYTES;

    // Get the first 4 bytes of the hash
    let sp1_verifier_vk_hash_prefix: [u8; 4] =
        Sha256::digest(sp1_verifier_vk)[..4].try_into().unwrap();

    // first, we need to zero out the first 3 bits of the hash
    let committed_values_digest =
        preprocess_public_inputs_hash(groth16_proof.sp1_public_inputs_hash.as_mut_slice());

    // next, we need to use the vkey hash and then processed input hash to generate the groth16 public input
    let groth16_public_inputs = groth16_public_values(&committed_values_digest);

    // Check the proof selector to match with SP1 V4 Groth16 VK Hash
    if sp1_verifier_vk_hash_prefix != groth16_proof.proof[..4] {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Verify the proof.
    verify_proof_raw(
        &groth16_proof.proof[4..],
        &groth16_public_inputs,
        sp1_verifier_vk,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Successfully verified proof!");

    Ok(())
}

fn preprocess_public_inputs_hash(sp1_public_inputs_hash: &mut [u8]) -> [u8; 32] {
    // The Groth16 verifier operates over a 254 bit field (BN254), so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    sp1_public_inputs_hash[0] = sp1_public_inputs_hash[0] & 0x1F;

    sp1_public_inputs_hash[0..32]
        .try_into()
        .expect("Invalid public input hash")
}

/// Formats the sp1 vkey hash and public inputs for use in the Groth16 verifier.
fn groth16_public_values(committed_values_digest: &[u8]) -> Vec<u8> {
    let vkey_hash_bytes = hex::decode(&DCAP_VKEY_HASH[2..]).unwrap();
    [
        vkey_hash_bytes[1..].to_vec(),
        committed_values_digest.to_vec(),
    ]
    .concat()
}
