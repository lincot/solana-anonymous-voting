use crate::{error::AnonVoteError, state::*, vk::VK_TALLY};
use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;

#[derive(Accounts)]
pub struct TallyBatch<'info> {
    #[account(mut)]
    tally: Account<'info, Tally>,
}

pub fn tally_batch(
    ctx: Context<TallyBatch>,
    proof: CompressedProof,
    root_after: [u8; 32],
    running_msg_hash_after: [u8; 32],
    tally_hash_after: [u8; 32],
) -> Result<()> {
    let tally = &mut ctx.accounts.tally;

    let proof = proof
        .decompress()
        .map_err(|_| AnonVoteError::ProofDecompressionError)?;
    let public_inputs = [
        root_after,
        running_msg_hash_after,
        tally_hash_after,
        tally.root,
        tally.running_msg_hash,
        tally.tally_hash,
    ];
    let mut v = Groth16Verifier::<6>::new(&proof.a, &proof.b, &proof.c, &public_inputs, &VK_TALLY)
        .map_err(|_| AnonVoteError::InvalidProof)?;
    v.verify().map_err(|_| AnonVoteError::InvalidProof)?;

    tally.root = root_after;
    tally.running_msg_hash = running_msg_hash_after;
    tally.tally_hash = tally_hash_after;

    Ok(())
}
