use anchor_lang::prelude::*;

// CHANGE ACCORDINGLY
pub const ECDSA_RISCZERO_DCAP_IMAGE_ID: [u8; 32] = [
    110, 182, 254, 70, 32, 14, 87, 112, 23, 19, 0, 233, 3, 198, 40, 9, 51, 39, 194, 255, 165, 195,
    3, 213, 168, 204, 179, 168, 148, 60, 75, 19,
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
