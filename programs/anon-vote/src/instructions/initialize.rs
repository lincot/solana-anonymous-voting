use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    #[account(
        init,
        space = PlatformConfig::DISCRIMINATOR.len() + PlatformConfig::INIT_SPACE,
        payer = payer,
        seeds = [&b"PLATFORM_CONFIG"[..]],
        bump,
    )]
    platform_config: Account<'info, PlatformConfig>,
    system_program: Program<'info, System>,
}

pub fn initialize(
    ctx: Context<Initialize>,
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
