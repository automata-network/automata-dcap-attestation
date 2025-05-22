use solana_program::program_error::ProgramError;

#[derive(Debug)]
pub enum DcapProgramError {
    /// The required signer is not provided in the instruction
    MissingRequiredSigner,
    /// The program is not the owner of the provided account
    InvalidAccountOwner,
    /// The provided account does not contain expected data
    InvalidAccountData,
    /// The provided zkvm selector does not match with a known zkVM
    UnknownZkVm,
    /// The proof fails to verify
    ProofVerificationFailure,
    /// The provided account does not match with a known account address
    AccountMismatch
}

impl From<DcapProgramError> for ProgramError {
    fn from(error: DcapProgramError) -> Self {
        ProgramError::Custom(error as u32)
    }
}