use anchor_lang::prelude::*;

#[error_code]
pub enum DcapVerifierError {
    #[msg("Invalid buffer owner")]
    InvalidOwner,

    #[msg("Buffer already complete")]
    BufferAlreadyComplete,

    #[msg("Invalid chunk index")]
    InvalidChunkIndex,

    #[msg("Chunk out of bounds")]
    ChunkOutOfBounds,

    #[msg("Incomplete quote")]
    IncompleteQuote,

    #[msg("Invalid quote")]
    InvalidQuote,

    #[msg("Invalid zkVM selector")]
    InvalidZkvmSelector,

    #[msg("Invalid zkVM program")]
    InvalidZkvmProgram,

    #[msg("Invalid zk proof")]
    InvalidZkProof,
    
    #[msg("Serialization error")]
    SerializationError,

    #[msg("Invalid hex string")]
    InvalidHexString,

    #[msg("Invalid SgxPckExtension")]
    InvalidSgxPckExtension,

    #[msg("Unsuccessful TcbStatus verification")]
    UnsuccessfulTcbStatusVerification,

    #[msg("Invalid Secp256r1 instruction")]
    InvalidSecp256r1Instruction,

    #[msg("The collateral has expired")]
    ExpiredCollateral,

    #[msg("Certificate has been revoked")]
    RevokedCertificate,

    #[msg("PCK FMSPC does not match")]
    MismatchFmspc,

    #[msg("PCK PCEID does not match")]
    MismatchPceid,
}
