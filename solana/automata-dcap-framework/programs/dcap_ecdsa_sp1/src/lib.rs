#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("Fb5vSs8XwQAopUnrVtMGnVciFaGT4J649nuR1i5kTPQH");

#[program]
pub mod dcap_ecdsa_sp1 {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
