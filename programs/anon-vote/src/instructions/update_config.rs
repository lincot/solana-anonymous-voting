use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    admin: Signer<'info>,
    #[account(mut, has_one = admin)]
    platform_config: Account<'info, PlatformConfig>,
}

pub fn update_config(
    ctx: Context<UpdateConfig>,
    admin: Pubkey,
    fee: u64,
    fee_destination: Pubkey,
) -> Result<()> {
    let platform_config = &mut ctx.accounts.platform_config;

    platform_config.admin = admin;
    platform_config.fee = fee;
    platform_config.fee_destination = fee_destination;

    Ok(())
}
