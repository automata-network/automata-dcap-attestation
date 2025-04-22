use anchor_lang::prelude::*;

pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    195, 54, 42, 227, 3, 203, 164, 20, 2, 98, 56, 154, 19, 9, 38, 80, 34, 158, 19, 99, 201, 231,
    226, 95, 119, 20, 8, 43, 81, 9, 212, 131,
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
