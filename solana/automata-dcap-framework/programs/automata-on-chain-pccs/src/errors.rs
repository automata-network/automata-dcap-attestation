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

    #[msg("Invalid digest")]
    InvalidDigest,

    #[msg("Invalid Hex String")]
    InvalidHexString,

    #[msg("Unauthorized")]
    Unauthorized,

    #[msg("Incomplete Buffer")]
    IncompleteBuffer,

    #[msg("Invalid Subject Certificate or CRL")]
    InvalidSubject,

    #[msg("Invalid Root Certificate")]
    InvalidRoot,

    #[msg("Unsupported ZKVM Selector")]
    UnsupportedZkvm,

    #[msg("Invalid Proof")]
    InvalidProof,

    #[msg("Failed to deserialize data")]
    FailedDeserialization,
}
