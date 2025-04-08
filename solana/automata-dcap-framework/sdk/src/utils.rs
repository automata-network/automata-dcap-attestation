use anchor_client::solana_sdk::instruction::Instruction;
use bytemuck::bytes_of;
use solana_secp256r1_program::Secp256r1SignatureOffsets;
use x509_cert::certificate::TbsCertificateInner;

pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

pub fn get_num_chunks(data_len: usize, chunk_size: usize) -> u8 {
    ((data_len as f64 / chunk_size as f64).ceil()) as u8
}

pub fn get_secp256r1_instruction(
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Instruction {

    assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len())
    );

    let num_signatures: u8 = 1;
    let pubkey_offset= DATA_START;
    let signature_offset = pubkey_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    let message_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);
    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    let offsets = Secp256r1SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: pubkey_offset as u16,
        public_key_instruction_index: u16::MAX,
        message_data_offset: message_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));

    debug_assert_eq!(instruction_data.len(), pubkey_offset);

    instruction_data.extend_from_slice(&pubkey);

    debug_assert_eq!(instruction_data.len(), signature_offset);

    instruction_data.extend_from_slice(&signature);

    debug_assert_eq!(instruction_data.len(), message_offset);

    instruction_data.extend_from_slice(message);

    Instruction {
        program_id: solana_secp256r1_program::ID,
        accounts: vec![],
        data: instruction_data,
    }

}

pub fn get_issuer_common_name(cert: &TbsCertificateInner) -> Option<String> {
    cert.issuer.0.iter()
        .find(|attr| attr.to_string().starts_with("CN="))
        .map(|attr| {
            let attr_string = attr.to_string();
            attr_string.split("CN=").nth(1).map(|s| s.to_string())
        })
        .flatten()
}
