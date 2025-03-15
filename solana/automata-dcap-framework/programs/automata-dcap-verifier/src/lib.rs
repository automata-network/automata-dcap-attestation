use anchor_lang::prelude::*;

declare_id!("9u6JzcNQtgyw2gMW4WDMnwVyz4Ju5eVqVfkTLnEgnfzh");

#[program]
pub mod automata_dcap_framework {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
