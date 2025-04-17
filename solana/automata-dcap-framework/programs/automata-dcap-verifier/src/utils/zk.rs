use anchor_lang::prelude::*;

// Temp: Subject to change
pub const RISCZERO_DCAP_IMAGE_UD: [u8; 32] = [
    214, 195, 180, 176, 143, 161, 99, 221, 68, 248, 145, 37, 249, 114, 35, 246, 247, 22, 62, 63,
    15, 98, 227, 96, 215, 7, 173, 171, 143, 107, 119, 153,
];
pub const SUCCINCT_DCAP_VKEY: [u8; 32] = [
    0, 54, 239, 213, 25, 187, 55, 27, 41, 164, 3, 34, 228, 0, 49, 131, 55, 22, 233, 68, 28, 105, 7,
    248, 174, 252, 94, 82, 206, 235, 201, 166,
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

    pub fn get_program_vkey(&self) -> Option<&'static [u8; 32]> {
        match self {
            ZkvmSelector::RiscZero => Some(&RISCZERO_DCAP_IMAGE_UD),
            ZkvmSelector::Succinct => Some(&SUCCINCT_DCAP_VKEY),
            _ => None,
        }
    }
}
