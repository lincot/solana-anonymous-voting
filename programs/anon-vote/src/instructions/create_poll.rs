use anchor_lang::prelude::*;
use zk_relayer::{
    cpi::{accounts::CreateRelayerState, create_relayer_state},
    program::ZkRelayer,
    state::ZkRelayerConfig,
};

use crate::{error::AnonVoteError, events::*, state::*, utils::system_transfer};

/// Maximum number of messages per voter per relayer.
const MSG_LIMIT: u64 = 3;
/// A year.
const MAX_POLL_DURATION: u64 = 365 * 24 * 60 * 60;
const N_RELAYERS: u64 = 1;

#[derive(Accounts)]
#[instruction(poll_id: u64, n_choices: u8, description_url: String, census_url_len: u32)]
pub struct CreatePoll<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    platform_config: Account<'info, PlatformConfig>,
    #[account(
        init,
        space = Poll::DISCRIMINATOR.len()
            + Poll::INIT_SPACE
            + Poll::added_space(n_choices, description_url.len(), census_url_len as usize),
        payer = payer,
        seeds = [&b"POLL"[..], &poll_id.to_le_bytes()],
        bump,
    )]
    poll: Account<'info, Poll>,
    relayer_config: Account<'info, ZkRelayerConfig>,
    /// CHECK: checked in CPI
    #[account(mut)]
    relayer_state: AccountInfo<'info>,
    /// CHECK: it's an empty signer account
    #[account(seeds = [b"ZK_RELAYER_SIGNER"], bump)]
    program_signer: AccountInfo<'info>,
    zk_relayer_program: Program<'info, ZkRelayer>,
    system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn create_poll(
    ctx: Context<CreatePoll>,
    id: u64,
    n_choices: u8,
    description_url: String,
    census_url: String,
    coordinator_key: Point,
    census_root: [u8; 32],
    voting_start_time: u64,
    voting_end_time: u64,
    fee: u64,
    fee_destination: Pubkey,
    n_voters: u64,
) -> Result<()> {
    let payer = &ctx.accounts.payer;
    let platform_config = &ctx.accounts.platform_config;
    let poll = &mut ctx.accounts.poll;
    let relayer_config = &ctx.accounts.relayer_config;
    let relayer_state = &ctx.accounts.relayer_state;
    let program_signer = &ctx.accounts.program_signer;
    let system_program = &ctx.accounts.system_program;
    let zk_relayer_program = &ctx.accounts.zk_relayer_program;

    require_gt!(n_choices, 0);

    require!(
        voting_end_time > voting_start_time
            && voting_end_time - voting_start_time <= MAX_POLL_DURATION,
        AnonVoteError::PollTooLong
    );

    poll.id = id;
    poll.n_choices = n_choices;
    poll.coordinator_key = coordinator_key;
    poll.census_root = census_root;
    poll.voting_start_time = voting_start_time;
    poll.voting_end_time = voting_end_time;
    poll.platform_fee = platform_config.fee;
    poll.fee = fee;
    poll.fee_destination = fee_destination;
    poll.description_url = description_url.clone();
    poll.census_url = census_url.clone();

    system_transfer(
        payer.to_account_info(),
        poll.to_account_info(),
        (relayer_config.fee + platform_config.fee) * MSG_LIMIT * N_RELAYERS * n_voters,
    )?;

    create_relayer_state(
        CpiContext::new_with_signer(
            zk_relayer_program.to_account_info(),
            CreateRelayerState {
                payer: payer.to_account_info(),
                relayer_config: relayer_config.to_account_info(),
                relayer_state: relayer_state.to_account_info(),
                program_signer: program_signer.to_account_info(),
                system_program: system_program.to_account_info(),
            },
            &[&[b"ZK_RELAYER_SIGNER", &[ctx.bumps.program_signer]]],
        ),
        crate::ID,
        id,
        MSG_LIMIT,
        voting_end_time,
    )?;

    emit!(CreatePollEvent {
        poll_id: poll.id,
        n_choices,
        coordinator_key,
        census_root,
        voting_start_time,
        voting_end_time,
        platform_fee: platform_config.fee,
        fee,
        fee_destination,
        n_voters,
        description_url,
        census_url,
    });

    Ok(())
}
