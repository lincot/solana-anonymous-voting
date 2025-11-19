use anchor_lang::prelude::*;
use core::iter::repeat;

use crate::{
    error::*,
    events::*,
    state::*,
    utils::{poseidon, u64_to_u256_be},
};

const MAX_CHOICES: usize = 8;

#[derive(Accounts)]
pub struct FinishTally<'info> {
    /// CHECK: it only receives funds
    #[account(mut)]
    payer: AccountInfo<'info>,
    #[account(mut, close = payer)]
    tally: Account<'info, Tally>,
    #[account(mut)]
    poll: Account<'info, Poll>,
}

pub fn finish_tally(ctx: Context<FinishTally>, tally: Vec<u64>, tally_salt: u64) -> Result<()> {
    let tally_acc = &ctx.accounts.tally;
    let poll = &mut ctx.accounts.poll;

    let now = Clock::get()?.unix_timestamp as u64;
    require!(now > poll.voting_end_time, AnonVoteError::BadTime);

    require!(
        tally.len() == poll.n_choices as usize,
        AnonVoteError::IncorrectTally
    );

    require!(
        tally_acc.running_msg_hash == poll.running_msg_hash,
        AnonVoteError::IncorrectTally
    );

    let mut preimage = Vec::with_capacity(tally.len() + 1);
    let tally_salt = u64_to_u256_be(tally_salt);
    preimage.push(&tally_salt[..]);
    let raw_tally_u128: Vec<_> = tally.iter().copied().map(u64_to_u256_be).collect();
    preimage.extend(raw_tally_u128.iter().map(|x| x.as_slice()));
    preimage.extend(repeat(&[0; 32][..]).take(MAX_CHOICES - poll.n_choices as usize));
    require!(
        poseidon(&preimage).map_err(|_| AnonVoteError::Poseidon)? == tally_acc.tally_hash,
        AnonVoteError::IncorrectTally
    );

    poll.tally = tally.clone();

    emit!(FinishTallyEvent {
        poll_id: poll.id,
        tally
    });

    Ok(())
}
