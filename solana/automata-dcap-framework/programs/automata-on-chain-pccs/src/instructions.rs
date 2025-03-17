use anchor_lang::prelude::*;

use crate::state::PckCertificate;

// Maximum size of the certificate data in bytes (4KB)
pub const MAX_CERT_DATA_SIZE: usize = 4096;


#[derive(Accounts)]
pub struct InitDataBuffer<'info> {

    /// The signer who will own this quote buffer.
    /// Must sign the transaction and pay for the account creation.
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    qe_id: String,
    pce_id: String,
    tcbm: String,
    cert_data: String
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
            qe_id.as_bytes(),
            pce_id.as_bytes(),
            tcbm.as_bytes(),
        ],
        bump,
    )]
    pub pck_certificate: Account<'info, PckCertificate>,

    pub system_program: Program<'info, System>,
}
