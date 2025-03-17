use crate::errors::DcapVerifierError;
use crate::state::DataBuffer;
use anchor_lang::prelude::*;

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
/// The space calculation (8 + 32 + 4 + 1 + 1 + 1 + 4 + 512 * 10) provides ~5KB
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
pub struct VerifyDcapQuote<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        constraint = quote_data_buffer.owner == *owner.key @ DcapVerifierError::InvalidOwner,
        constraint = quote_data_buffer.complete @ DcapVerifierError::IncompleteQuote,
    )]
    pub quote_data_buffer: Account<'info, DataBuffer>,
}
