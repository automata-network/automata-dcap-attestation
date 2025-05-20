use anchor_lang::prelude::*;

// CHANGE ACCORDINGLY
pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    243, 74, 234, 75, 15, 194, 110, 17, 180, 178, 57, 194, 146, 83, 200, 104, 136, 124, 175, 5, 114, 193, 108, 110, 69, 251, 20, 162, 81, 233, 111, 246
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
