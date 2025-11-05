use anchor_lang::prelude::*;

use crate::state::*;

#[event(discriminator = 0u8)]
#[derive(Clone, Debug)]
pub struct VoteEvent {
    pub poll_id: u64,
    pub eph_key: Point,
    pub nonce: u64,
    pub ciphertext: [[u8; 32]; 7],
    pub msg_hash: [u8; 32],
}

#[event(discriminator = 1u8)]
#[derive(Clone, Debug)]
pub struct CreatePollEvent {
    pub poll_id: u64,
    pub n_choices: u8,
    pub coordinator_key: Point,
    pub census_root: [u8; 32],
    pub voting_start_time: u64,
    pub voting_end_time: u64,
    pub platform_fee: u64,
    pub fee: u64,
    pub fee_destination: Pubkey,
    pub n_voters: u64,
    pub description_url: String,
    pub census_url: String,
}

#[event(discriminator = 2u8)]
#[derive(Clone, Debug)]
pub struct FinishTallyEvent {
    pub poll_id: u64,
    pub tally: Vec<u64>,
}
