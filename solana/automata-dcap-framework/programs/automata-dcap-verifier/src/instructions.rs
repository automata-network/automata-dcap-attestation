use anchor_lang::prelude::*;
use crate::errors::DcapVerifierError;
use crate::state::{DataBuffer, QeTcbStatus, VerifiedOutput};
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_SYSVAR_ID;
use automata_on_chain_pccs::state::{EnclaveIdentity, TcbInfo};

#[derive(Accounts)]
pub struct Initialize {}

/// Accounts required for initializing a quote buffer.
///
/// This instruction creates a new on-chain account that will store DCAP
/// attestation quote data. Since DCAP quotes (typically 4-6 KB) exceed
/// Solana's transaction size limits, the quote is broken into chunks and
/// stored in this account. Once all chunks are received, the quote can be
/// verified in a single instruction.
///
/// The space calculation (8 + 32 + 4 + 1 + 1 + 1 + 4 + 1024 * 9) provides ~9KB
/// of storage and breaks down as:
/// - 8 bytes: Account discriminator (Anchor identifier)
/// - 32 bytes: Pubkey for the owner
/// - 4 bytes: u32 for total_size
/// - 1 byte: u8 for num_chunks
/// - 1 byte: u8 for chunks_received
/// - 1 byte: bool for complete flag
/// - 4 bytes: Vec length prefix
/// - 1024 * 9 bytes: Storage for quote data (~9KB)
#[derive(Accounts)]
pub struct InitQuoteBuffer<'info> {
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
        space = 8 + 32 + 4 + 1 + 1 + 1 + 4 + 1024 * 9,
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    /// Required by the system program for account creation.
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct AddQuoteChunk<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(mut)]
    pub data_buffer: Account<'info, DataBuffer>,
}

#[derive(Accounts)]
pub struct VerifyDcapQuoteIntegrity<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = quote_data_buffer.owner == *owner.key @ DcapVerifierError::InvalidOwner,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct VerifyDcapQuoteIsvSignature<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = quote_data_buffer.owner == *owner.key @ DcapVerifierError::InvalidOwner,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(qe_type: String,  version: u8)]
pub struct VerifyDcapQuoteEnclaveSource<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = quote_data_buffer.owner == *owner.key @ DcapVerifierError::InvalidOwner,
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
        init_if_needed,
        payer = owner,
        space = 8 + 64 + 1,
        seeds = [
            b"qe_tcb_status",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub qe_tcb_status_pda: Account<'info, QeTcbStatus>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(tcb_type: String , version: u8, fmspc: [u8; 6])]
pub struct VerifyDcapQuoteTcbStatus<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = quote_data_buffer.owner == *owner.key @ DcapVerifierError::InvalidOwner,
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
        seeds = [
            b"qe_tcb_status",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
        seeds::program = crate::ID,
    )]
    pub qe_tcb_status_pda: Account<'info, QeTcbStatus>,

    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + 32 + 2 + 4 + 4 + 50 + 600 + 1024,
        seeds = [
            b"verified_output",
            quote_data_buffer.key().as_ref(),
        ],
        bump,
    )]
    pub verified_output: Account<'info, VerifiedOutput>,

    pub system_program: Program<'info, System>,
}
