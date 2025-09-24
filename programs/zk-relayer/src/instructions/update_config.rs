use crate::{
    state::*,
    utils::{system_transfer, transfer},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(relayer_endpoint_len: u32)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    admin: Signer<'info>,
    #[account(mut, has_one = admin)]
    relayer_config: Account<'info, ZkRelayerConfig>,
    system_program: Program<'info, System>,
}

pub fn update_config(
    ctx: Context<UpdateConfig>,
    relayer: Relayer,
    admin: Pubkey,
    fee: u64,
) -> Result<()> {
    let payer = &mut ctx.accounts.payer;
    let relayer_config = &mut ctx.accounts.relayer_config;

    let rent = Rent::get()?.minimum_balance(
        relayer_config
            .relayer
            .endpoint
            .len()
            .abs_diff(relayer.endpoint.len()),
    );
    if relayer_config.relayer.endpoint.len() < relayer.endpoint.len() {
        system_transfer(
            payer.to_account_info(),
            relayer_config.to_account_info(),
            rent,
        )?;
    } else {
        transfer(relayer_config.as_ref(), payer, rent)?;
    }

    relayer_config.admin = admin;
    relayer_config.fee = fee;
    relayer_config.relayer = relayer;

    Ok(())
}
