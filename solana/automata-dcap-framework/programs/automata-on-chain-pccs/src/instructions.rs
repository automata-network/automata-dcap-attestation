use anchor_lang::prelude::*;

use crate::state::{DataBuffer, PckCertificate, PcsCertificate, CertificateAuthority};
use crate::errors::PccsError;

// Maximum size of the certificate data in bytes (4KB)
pub const MAX_CERT_DATA_SIZE: usize = 4096;


#[derive(Accounts)]
#[instruction(
    total_size: u32,
    num_chunks: u8,
)]
pub struct InitDataBuffer<'info> {

    /// The signer who will own this quote buffer.
    /// Must sign the transaction and pay for the account creation.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The account that will store the chunked data.
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 4 + 1 + 1 + 1 + 4 + total_size as usize,
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    /// Required by the system program for account creation.
    pub system_program: Program<'info, System>,
}

/// An instruction to add a chunk of data to the data buffer.
#[derive(Accounts)]
#[instruction(
    chunk_index: u8,
    chunk_data: Vec<u8>,
    offset: u32,
)]
pub struct AddDataChunk<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(mut)]
    pub data_buffer: Account<'info, DataBuffer>,
}


#[derive(Accounts)]
#[instruction(
    qe_id: String,
    pce_id: String,
    tcbm: String,
)]
pub struct UpsertPckCertificate<'info> {

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 1 + 16 + 2 + 18 + MAX_CERT_DATA_SIZE,
        seeds = [
            b"pck_cert",
            &qe_id.as_bytes()[..8],
            &pce_id.as_bytes()[..2],
            &tcbm.as_bytes()[..8],
        ],
        bump,
    )]
    pub pck_certificate: Account<'info, PckCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ca_type: CertificateAuthority)]
pub struct UpsertPcsCertificate<'info> {

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 1 + MAX_CERT_DATA_SIZE,
        seeds = [b"pcs_cert", ca_type.common_name().as_bytes()],
        bump,
    )]
    pub pcs_certificate: Account<'info, PcsCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    pub system_program: Program<'info, System>,
}
