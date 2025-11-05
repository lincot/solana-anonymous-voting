use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(poll_id: u64)]
pub struct CreateTally<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = Tally::DISCRIMINATOR.len() + Tally::INIT_SPACE,
        payer = payer,
        seeds = [&b"TALLY"[..], &poll_id.to_le_bytes(), &payer.key.to_bytes()],
        bump,
    )]
    tally: Account<'info, Tally>,
    system_program: Program<'info, System>,
}

pub fn create_tally(
    ctx: Context<CreateTally>,
    _poll_id: u64,
    initial_tally_hash: [u8; 32],
) -> Result<()> {
    ctx.accounts.tally.set_inner(Tally {
        tally_hash: initial_tally_hash,
        running_msg_hash: [0; 32],
        root: [0; 32],
    });

    Ok(())
}
