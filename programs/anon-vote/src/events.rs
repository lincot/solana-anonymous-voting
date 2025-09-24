use anchor_lang::prelude::*;

use crate::state::*;

#[event(discriminator = 0u8)]
#[derive(Debug)]
pub struct VoteEvent {
    pub eph_key: Point,
    pub nonce: u64,
    pub ciphertext: [[u8; 32]; 7],
}
