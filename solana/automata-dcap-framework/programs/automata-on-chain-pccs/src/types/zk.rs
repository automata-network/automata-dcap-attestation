use anchor_lang::prelude::*;

// CHANGE ACCORDINGLY
pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    142, 98, 215, 67, 51, 255, 193, 109, 192, 252, 184, 186, 221, 241, 183, 241, 169, 32, 73, 198,
    200, 16, 109, 246, 65, 101, 82, 156, 246, 89, 70, 110,
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
