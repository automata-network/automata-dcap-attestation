use anchor_lang::prelude::*;

#[error_code]
pub enum PccsError {
    #[msg("Invalid CA type")]
    InvalidCaType,

    #[msg("Invalid Hex String")]
    InvalidHexString,
}
