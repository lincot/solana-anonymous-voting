#![allow(unexpected_cfgs)]
#![allow(clippy::manual_repeat_n)]
// fixes `#[program]` warning
#![allow(deprecated)]

use anchor_lang::prelude::*;

use crate::{instructions::*, state::*};

pub mod error;
pub mod events;
mod instructions;
pub mod state;
mod utils;
mod vk;

declare_id!("MootG8ueTooVorJJq3kxdXLLg59ZW6phaHpoWeSySqB");

#[program]
pub mod anon_vote {
    use super::*;

    #[instruction(discriminator = 0u8)]
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        fee: u64,
        fee_destination: Pubkey,
    ) -> Result<()> {
        instructions::initialize(ctx, admin, fee, fee_destination)
    }

    #[instruction(discriminator = 1u8)]
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        admin: Pubkey,
        fee: u64,
        fee_destination: Pubkey,
    ) -> Result<()> {
        instructions::update_config(ctx, admin, fee, fee_destination)
    }

    #[instruction(discriminator = 2u8)]
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
        instructions::create_poll(
            ctx,
            id,
            n_choices,
            description_url,
            census_url,
            coordinator_key,
            census_root,
            voting_start_time,
            voting_end_time,
            fee,
            fee_destination,
            n_voters,
        )
    }

    #[instruction(discriminator = 3u8)]
    pub fn vote(
        ctx: Context<Vote>,
        eph_key: Point,
        nonce: u64,
        ciphertext: [[u8; 32]; 7],
        proof: CompressedProof,
    ) -> Result<()> {
        instructions::vote(ctx, eph_key, nonce, ciphertext, proof)
    }

    #[instruction(discriminator = 4u8)]
    #[allow(clippy::too_many_arguments)]
    pub fn vote_with_relayer(
        ctx: Context<VoteWithRelayer>,
        relayer_nu_hash: [u8; 32],
        msg_hash: [u8; 32],
        relayer_id: [u8; 32],
        eph_key: Point,
        nonce: u64,
        ciphertext: [[u8; 32]; 7],
        proof: CompressedProof,
    ) -> Result<()> {
        instructions::vote_with_relayer(
            ctx,
            relayer_nu_hash,
            msg_hash,
            relayer_id,
            eph_key,
            nonce,
            ciphertext,
            proof,
        )
    }

    #[instruction(discriminator = 5u8)]
    pub fn create_tally(
        ctx: Context<CreateTally>,
        poll_id: u64,
        initial_tally_hash: [u8; 32],
    ) -> Result<()> {
        instructions::create_tally(ctx, poll_id, initial_tally_hash)
    }

    #[instruction(discriminator = 6u8)]
    pub fn tally_batch(
        ctx: Context<TallyBatch>,
        proof: CompressedProof,
        root_after: [u8; 32],
        running_msg_hash_after: [u8; 32],
        tally_hash_after: [u8; 32],
    ) -> Result<()> {
        instructions::tally_batch(
            ctx,
            proof,
            root_after,
            running_msg_hash_after,
            tally_hash_after,
        )
    }

    #[instruction(discriminator = 7u8)]
    pub fn finish_tally(ctx: Context<FinishTally>, tally: Vec<u64>, tally_salt: u64) -> Result<()> {
        instructions::finish_tally(ctx, tally, tally_salt)
    }

    #[instruction(discriminator = 8u8)]
    pub fn close_tally(ctx: Context<CloseTally>, poll_id: u64) -> Result<()> {
        instructions::close_tally(ctx, poll_id)
    }

    #[instruction(discriminator = 9u8)]
    pub fn withdraw_poll(ctx: Context<WithdrawPoll>) -> Result<()> {
        instructions::withdraw_poll(ctx)
    }
}
