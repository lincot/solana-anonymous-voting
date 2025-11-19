use anchor_lang::prelude::*;

use crate::{error::*, state::*, ALLOWED_PROGRAMS};

const HASH_0_0: [u8; 32] = [
    32, 152, 245, 251, 158, 35, 158, 171, 60, 234, 195, 242, 123, 129, 228, 129, 220, 49, 36, 213,
    95, 254, 213, 35, 168, 57, 238, 132, 70, 182, 72, 100,
];

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

    relayer_state.root_state = HASH_0_0;
    relayer_state.msg_limit = msg_limit;
    relayer_state.end_time = end_time;
    relayer_state.fee = relayer_config.fee;

    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_poseidon::PoseidonSyscallError;

    use super::*;

    /// Poseidon hash a [maximum of 12 elements](https://github.com/anza-xyz/agave/blob/4a35485d867e8b6d896e8e1ef91e165839f652ed/syscalls/src/lib.rs#L1718).
    fn poseidon(inputs: &[&[u8]]) -> core::result::Result<[u8; 32], PoseidonSyscallError> {
        solana_poseidon::hashv(
            solana_poseidon::Parameters::Bn254X5,
            solana_poseidon::Endianness::BigEndian,
            inputs,
        )
        .map(|x| x.0)
    }

    #[test]
    fn test_hash_0_0() {
        assert_eq!(HASH_0_0, poseidon(&[&[0; 32], &[0; 32]]).unwrap());
    }
}
