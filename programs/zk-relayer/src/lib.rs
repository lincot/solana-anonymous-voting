#![allow(unexpected_cfgs)]
#![allow(clippy::too_many_arguments)]
// fixes `#[program]` warning
#![allow(deprecated)]

use anchor_lang::prelude::*;

use crate::{instructions::*, state::*};

pub mod error;
mod instructions;
pub mod state;
mod utils;
mod vk;

declare_id!("re1AjD8N1s4qZdKqJGNCjWRWcRS6jWoxVGw2ZXoMn7u");

/// The list of allowed programs. Relayer has to trust the program, otherwise
/// a transaction could fail and waste network fee. Transaction simulation
/// wouldn't help with that.
const ALLOWED_PROGRAMS: &[Pubkey] = &[pubkey!("MootG8ueTooVorJJq3kxdXLLg59ZW6phaHpoWeSySqB")];

#[program]
pub mod zk_relayer {
    use super::*;

    #[instruction(discriminator = 0u8)]
    pub fn initialize(
        ctx: Context<Initialize>,
        relayer: Relayer,
        admin: Pubkey,
        fee: u64,
    ) -> Result<()> {
        instructions::initialize(ctx, relayer, admin, fee)
    }

    #[instruction(discriminator = 1u8)]
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        relayer: Relayer,
        admin: Pubkey,
        fee: u64,
    ) -> Result<()> {
        instructions::update_config(ctx, relayer, admin, fee)
    }

    #[instruction(discriminator = 2u8)]
    pub fn create_relayer_state(
        ctx: Context<CreateRelayerState>,
        target_program: Pubkey,
        state_id: u64,
        msg_limit: u64,
        end_time: u64,
    ) -> Result<()> {
        instructions::create_relayer_state(ctx, target_program, state_id, msg_limit, end_time)
    }

    #[instruction(discriminator = 3u8)]
    pub fn relay<'info>(
        ctx: Context<'_, '_, '_, 'info, Relay<'info>>,
        state_id: u64,
        proof: CompressedProof,
        root_after: [u8; 32],
        msg_hash: [u8; 32],
        discriminator: u8,
        eph_key: Point,
        nonce: u64,
        ciphertext_hash: [u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        instructions::relay(
            ctx,
            state_id,
            proof,
            root_after,
            msg_hash,
            discriminator,
            eph_key,
            nonce,
            ciphertext_hash,
            data,
        )
    }
}
