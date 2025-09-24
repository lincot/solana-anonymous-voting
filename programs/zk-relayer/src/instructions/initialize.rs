use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(relayer_endpoint_len: u32)]
pub struct Initialize<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    #[account(
        init,
        space = ZkRelayerConfig::DISCRIMINATOR.len()
            + ZkRelayerConfig::INIT_SPACE
            + ZkRelayerConfig::added_space(relayer_endpoint_len as usize),
        payer = payer,
        seeds = [&b"RELAYER_CONFIG"[..]],
        bump,
    )]
    relayer_config: Account<'info, ZkRelayerConfig>,
    system_program: Program<'info, System>,
}

pub fn initialize(
    ctx: Context<Initialize>,
    relayer: Relayer,
    admin: Pubkey,
    fee: u64,
) -> Result<()> {
    let relayer_config = &mut ctx.accounts.relayer_config;

    relayer_config.admin = admin;
    relayer_config.fee = fee;
    relayer_config.relayer = relayer;

    Ok(())
}
