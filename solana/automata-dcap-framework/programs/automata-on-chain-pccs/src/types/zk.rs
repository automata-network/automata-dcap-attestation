use anchor_lang::prelude::*;

// CHANGE ACCORDINGLY
pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    165, 2, 89, 201, 182, 242, 184, 70, 57, 99, 36, 21, 203, 248, 148, 205, 110, 230, 42, 229, 216,
    1, 250, 117, 2, 9, 180, 117, 204, 205, 140, 172,
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
