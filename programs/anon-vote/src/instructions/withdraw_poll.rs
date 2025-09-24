use anchor_lang::prelude::*;

use crate::{error::AnonVoteError, state::*, utils::transfer};

#[derive(Accounts)]
pub struct WithdrawPoll<'info> {
    /// CHECK: checked using has_one
    #[account(mut)]
    fee_destination: AccountInfo<'info>,
    #[account(mut, has_one = fee_destination)]
    poll: Account<'info, Poll>,
}

pub fn withdraw_poll(ctx: Context<WithdrawPoll>) -> Result<()> {
    let fee_destination = &ctx.accounts.fee_destination;
    let poll = &ctx.accounts.poll;

    let now = Clock::get()?.unix_timestamp as u64;
    require!(now >= poll.voting_end_time, AnonVoteError::BadTime);

    let rent = Rent::get()?.minimum_balance(AsRef::<AccountInfo>::as_ref(poll).data_len());
    transfer(poll.as_ref(), fee_destination, poll.get_lamports() - rent)?;

    Ok(())
}
