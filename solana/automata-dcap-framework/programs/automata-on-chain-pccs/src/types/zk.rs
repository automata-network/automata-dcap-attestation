use anchor_lang::prelude::*;

// CHANGE ACCORDINGLY
pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    228, 36, 18, 186, 123, 93, 202, 136, 178, 76, 237, 0, 161, 55, 201, 176, 136, 214, 163, 243,
    124, 103, 84, 183, 4, 9, 29, 184, 14, 89, 203, 19,
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
            ZkvmSelector::RiscZero => Some(&ECDSA_RISCZERO_DCAP_IMAGE_ID),
            _ => None,
        }
    }
}
