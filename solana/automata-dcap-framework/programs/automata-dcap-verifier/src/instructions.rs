use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_SYSVAR_ID;
use automata_on_chain_pccs::types::CertificateAuthority;

use crate::errors::DcapVerifierError;
use crate::state::{DataBuffer, VerifiedOutput};
use crate::utils::zk::ZkvmSelector;

use automata_on_chain_pccs::state::{EnclaveIdentity, TcbInfo, PcsCertificate};

/// This instruction creates a new on-chain account that will store DCAP
/// attestation quote data. Since DCAP quotes (typically 4-6 KB) exceed
/// Solana's transaction size limits, the quote is broken into chunks and
/// stored in this account. Once all chunks are received, the quote can be
/// verified in a single instruction.
///
/// The space calculation (8 + 32 + 4 + 1 + 4 + quote_size)
/// of storage and breaks down as:
/// - 8 bytes: Account discriminator (Anchor identifier)
/// - 32 bytes: Pubkey for the owner
/// - 4 bytes: u32 for total_size
/// - 1 byte: bool for complete flag
/// - 4 bytes: Vec length prefix
/// - quote_size: The size of the quote data, explicitly provided in the instruction
///
/// This instruction also creates the VerifiedOutput account, which is used
/// to store the result of the DCAP Quote verification.
///
/// The space calculation (8 + 2 + 4 + 6 + 4 + 584 (max) + 1 + 1 + 1 + 3 * 64 + 512 bytes)
/// Breaks down as:
/// - 8 bytes: Account discriminator (Anchor identifier)
/// - 2 bytes: u16 for quote_version
/// - 4 bytes: u32 for tee_type
/// - 6 bytes: [u8; 6] for fmspc
/// - 4 bytes: Vec length prefix
/// - 584 bytes: ISV or TD10 Report Body (max size)
/// - 1 byte: bool for integrity_verified
/// - 1 byte: bool for isv_signature_verified
/// - 1 byte: bool for pck_cert_chain_verified
/// - 3 * 64 bytes: Strings for fmspc_tcb_status, tdx_module_tcb_status, and qe_tcb_status
/// - 512 bytes: Optional advisory_ids (tentative size)
#[derive(Accounts)]
#[instruction(quote_size: u32)]
pub struct Create<'info> {
    /// The signer who will own this quote buffer.
    /// Must sign the transaction and pay for account creation.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The account that will store the DCAP quote data.
    /// This is initialized with the specified space and
    /// owned by the program.
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 4 + 1 + 4 + quote_size as usize,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    /// The account that will store the result of the DCAP quote verification
    #[account(
        init,
        payer = owner,
        space = 8 + 2 + 4 + 6 + 4 + 584 + 1 + 1 + 1 + 3 * 64 + 512,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    /// Required by the system program for account creation.
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(chunk_data: Vec<u8>, offset: u32)]
pub struct AddQuoteChunk<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = data_buffer.owner == owner.key() @ DcapVerifierError::InvalidOwner,
        constraint = data_buffer.complete == false @ DcapVerifierError::BufferAlreadyComplete,
        constraint = (offset as usize + chunk_data.len()) as u32 <= data_buffer.total_size @ DcapVerifierError::ChunkOutOfBounds
    )]
    pub data_buffer: Account<'info, DataBuffer>,
}

#[derive(Accounts)]
pub struct VerifyDcapQuoteIntegrity<'info> {
    #[account(
        mut,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    #[account(
        mut,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    pub system_program: Program<'info, System>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct VerifyDcapQuoteIsvSignature<'info> {
    #[account(
        mut,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    #[account(
        mut,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(qe_type: String,  version: u8)]
pub struct VerifyDcapQuoteEnclaveSource<'info> {
    #[account(
        mut,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [
            b"enclave_identity",
            qe_type.as_bytes(),
            &version.to_le_bytes()[..1],
        ],
        bump,
        seeds::program = automata_on_chain_pccs::ID,
    )]
    pub qe_identity_pda: Account<'info, EnclaveIdentity>,

    #[account(
        mut,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    zkvm_selector: ZkvmSelector,
    proof_bytes: Vec<u8>,
)]
pub struct VerifyPckCertChainZk<'info> {
    #[account(
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    /// CHECK: The program checks the address of the PCK CRL account
    pub pck_crl: Account<'info, PcsCertificate>,

    #[account(
        seeds = [
            b"pcs_cert",
            CertificateAuthority::ROOT.common_name().as_bytes(),
            &[true as u8]
        ],
        bump,
        seeds::program = automata_on_chain_pccs::ID,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,
    
    #[account(
        mut,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(tcb_type: String , version: u8, fmspc: [u8; 6])]
pub struct VerifyDcapQuoteTcbStatus<'info> {
    #[account(
        mut,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [
            b"tcb_info",
            tcb_type.as_bytes(),
            &version.to_le_bytes()[..1],
            &fmspc,
        ],
        bump,
        seeds::program = automata_on_chain_pccs::ID,
    )]
    pub tcb_info_pda: Account<'info, TcbInfo>,

    #[account(
        mut,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    pub system_program: Program<'info, System>,
}

/// This instruction closes both the quote buffer and the verified output accounts
/// and transfers any remaining lamports back to the owner.
#[derive(Accounts)]
pub struct CloseQuoteBuffer<'info> {
    /// The owner of the quote buffer and verified output accounts.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The quote buffer account to be closed.
    #[account(
        mut,
        close = owner,
        constraint = quote_data_buffer.owner == owner.key() @ DcapVerifierError::InvalidOwner,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    /// The verified output account to be closed.
    #[account(
        mut,
        close = owner,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    /// The system program account, required for closing accounts.
    pub system_program: Program<'info, System>,
}
