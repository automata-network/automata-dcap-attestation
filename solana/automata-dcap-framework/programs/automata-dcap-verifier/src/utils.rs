use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use solana_sdk_ids::secp256r1_program::ID as SEC256R1_PROGRAM_ID;

use crate::errors::DcapVerifierError;


#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct Secp256r1SignatureOffsets {
    signature_offset: u16,
    signature_instruction_index: u16,
    public_key_offset: u16,
    public_key_instruction_index: u16,
    message_data_offset: u16,
    message_data_size: u16,
    message_instruction_index: u16,
}


/// Verify the Secp256r1Program Instruction Fields
pub fn verify_secp256r1_program_instruction_fields(
    instruction: &Instruction,
    message: &[u8],
    compressed_key: &[u8],
    normalized_sig: &[u8]
) -> Result<()> {

    if instruction.program_id != SEC256R1_PROGRAM_ID ||
        instruction.accounts.len() != 0 ||
        instruction.data.len() != (16 + 64 + 33 + message.len()) {
        return Err(DcapVerifierError::InvalidSecp256r1Instruction.into());
    }

    let instruction_data = &instruction.data;

    // Verify the number of signatures is 1
    let num_signatures = instruction_data[0];
    if num_signatures != 1 {
        return Err(DcapVerifierError::InvalidSecp256r1Instruction.into());
    }

    // Parse the Secp256r1SignatureOffsets
    let offsets: Secp256r1SignatureOffsets = Secp256r1SignatureOffsets::try_from_slice(
        &instruction_data[2..16]
    )?;

    // verify pubkey
    let pubkey_start = offsets.public_key_offset as usize;
    let pubkey_end = pubkey_start + compressed_key.len();
    let pubkey_matched = &instruction_data[pubkey_start..pubkey_end] == compressed_key;
    if !pubkey_matched {
        return Err(DcapVerifierError::InvalidSecp256r1Instruction.into());
    }

    // Verify signature
    let sig_start = offsets.signature_offset as usize;
    let sig_end = sig_start + normalized_sig.len();
    let sig_matched = &instruction_data[sig_start..sig_end] == normalized_sig;
    if !sig_matched {
        return Err(DcapVerifierError::InvalidSecp256r1Instruction.into());
    }

    // Verify message
    let msg_start = offsets.message_data_offset as usize;
    let msg_end = msg_start + offsets.message_data_size as usize;
    let msg_matched = &instruction_data[msg_start..msg_end] == message;
    if !msg_matched {
        return Err(DcapVerifierError::InvalidSecp256r1Instruction.into());
    }

    Ok(())
}
