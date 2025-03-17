use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

declare_id!("H2w3Z4HMFws4VswB812AA5RvgaESGHTGWffSPRvcAoJn");

use errors::*;
use instructions::*;

#[program]
pub mod automata_on_chain_pccs {
    use crate::instructions::UpsertPckCertificate;

    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }

    pub fn upsert_pck_certificate(
        ctx: Context<UpsertPckCertificate>,
        qe_id: String,
        pce_id: String,
        tcbm: String,
        cert_data: String,
    ) -> Result<()> {
        let pck_certificate = &mut ctx.accounts.pck_certificate;

        pck_certificate.qe_id = hex::decode(qe_id)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;
        pck_certificate.pce_id = hex::decode(pce_id)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;
        pck_certificate.tcbm = hex::decode(tcbm)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;

        pck_certificate.cert_data = cert_data;

        msg!(
            "PCK certificate upserted to {}",
            ctx.accounts.pck_certificate.key()
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
