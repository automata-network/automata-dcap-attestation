use anchor_lang::prelude::*;

#[error_code]
pub enum PccsError {
    #[msg("Invalid owner")]
    InvalidOwner,

    #[msg("Buffer already complete")]
    BufferAlreadyComplete,

    #[msg("Invalid chunk index")]
    InvalidChunkIndex,

    #[msg("Chunk out of bounds")]
    ChunkOutOfBounds,

    #[msg("Invalid Hex String")]
    InvalidHexString,

    #[msg("Unauthorized")]
    Unauthorized,

    #[msg("Incomplete Buffer")]
    IncompleteBuffer,
}
