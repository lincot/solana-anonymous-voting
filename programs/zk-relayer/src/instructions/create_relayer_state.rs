use anchor_lang::prelude::*;

use crate::{error::*, state::*, ALLOWED_PROGRAMS};

#[derive(Accounts)]
#[instruction(target_program: Pubkey, state_id: u64)]
pub struct CreateRelayerState<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    relayer_config: Account<'info, ZkRelayerConfig>,
    #[account(
        init,
        space = RelayerState::DISCRIMINATOR.len()
            + RelayerState::INIT_SPACE,
        payer = payer,
        seeds = [&b"RELAYER_STATE"[..], &target_program.to_bytes(), &state_id.to_le_bytes()],
        bump,
    )]
    relayer_state: Account<'info, RelayerState>,
    #[account(
        seeds = [b"ZK_RELAYER_SIGNER"],
        seeds::program = target_program,
        bump,
        constraint = ALLOWED_PROGRAMS.contains(&target_program)
            @ ZkRelayerError::ProgramNotAllowed,
    )]
    program_signer: Signer<'info>,
    system_program: Program<'info, System>,
}

pub fn create_relayer_state(
    ctx: Context<CreateRelayerState>,
    _target_program: Pubkey,
    _state_id: u64,
    msg_limit: u64,
    end_time: u64,
) -> Result<()> {
    let relayer_config = &ctx.accounts.relayer_config;
    let relayer_state = &mut ctx.accounts.relayer_state;

    relayer_state.msg_limit = msg_limit;
    relayer_state.end_time = end_time;
    relayer_state.fee = relayer_config.fee;

    Ok(())
}
