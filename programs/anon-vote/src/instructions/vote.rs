use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use zk_relayer::state::RelayerState;

use crate::{error::AnonVoteError, events::VoteEvent, state::*, utils::*, vk::VK_VOTE};

const RELAYER_PROGRAM: Pubkey = pubkey!("re1AjD8N1s4qZdKqJGNCjWRWcRS6jWoxVGw2ZXoMn7u");

#[derive(Accounts)]
pub struct Vote<'info> {
    #[account(mut)]
    payer: Signer<'info>,
    /// CHECK: the address is checked
    #[account(mut, address = vote_common.poll.fee_destination)]
    poll_fee_destination: AccountInfo<'info>,
    vote_common: VoteCommon<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VoteWithRelayer<'info> {
    #[account(mut)]
    relayer: Signer<'info>,
    #[account(
        signer,
        seeds = [&b"RELAYER_STATE"[..], &crate::ID.to_bytes(), &vote_common.poll.id.to_le_bytes()],
        seeds::program = RELAYER_PROGRAM,
        bump,
    )]
    relayer_state: Account<'info, RelayerState>,
    vote_common: VoteCommon<'info>,
}

pub fn vote(
    ctx: Context<Vote>,
    eph_key: Point,
    nonce: u64,
    ciphertext: [[u8; 32]; 7],
    proof: CompressedProof,
) -> Result<()> {
    let common = &mut ctx.accounts.vote_common;
    let payer = &ctx.accounts.payer;
    let poll_fee_destination = &ctx.accounts.poll_fee_destination;
    let poll = &mut common.poll;
    let platform_fee_destination = &common.platform_fee_destination;

    system_transfer(
        payer.to_account_info(),
        poll_fee_destination.to_account_info(),
        poll.fee,
    )?;
    system_transfer(
        payer.to_account_info(),
        platform_fee_destination.to_account_info(),
        poll.platform_fee,
    )?;

    let relayer_ciphertext_hash = [0; 32];
    let relayer_decrypt_key = Point::default();

    vote_common(
        eph_key,
        nonce,
        ciphertext,
        proof,
        relayer_ciphertext_hash,
        relayer_decrypt_key,
        None,
        common,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vote_with_relayer(
    ctx: Context<VoteWithRelayer>,
    eph_key: Point,
    nonce: u64,
    relayer_ciphertext_hash: [u8; 32],
    msg_hash: [u8; 32],
    relayer_decrypt_key: Point,
    ciphertext: [[u8; 32]; 7],
    proof: CompressedProof,
) -> Result<()> {
    let relayer = &ctx.accounts.relayer;
    let relayer_state = &ctx.accounts.relayer_state;

    let common = &mut ctx.accounts.vote_common;

    transfer(common.poll.as_ref(), relayer, relayer_state.fee)?;
    transfer(
        common.poll.as_ref(),
        &common.platform_fee_destination,
        common.platform_config.fee,
    )?;

    vote_common(
        eph_key,
        nonce,
        ciphertext,
        proof,
        relayer_ciphertext_hash,
        relayer_decrypt_key,
        Some(msg_hash),
        common,
    )
}

#[allow(clippy::too_many_arguments)]
fn vote_common(
    eph_key: Point,
    nonce: u64,
    ciphertext: [[u8; 32]; 7],
    proof: CompressedProof,
    relayer_ciphertext_hash: [u8; 32],
    relayer_decrypt_key: Point,
    msg_hash_from_relayer: Option<[u8; 32]>,
    common: &mut VoteCommon<'_>,
) -> Result<()> {
    let poll = &mut common.poll;

    let now = Clock::get()?.unix_timestamp as u64;
    require!(
        (poll.voting_start_time..=poll.voting_end_time).contains(&now),
        AnonVoteError::BadTime
    );

    let mut preimage = [&eph_key.x[..]; 10];
    preimage[0] = &eph_key.x;
    preimage[1] = &eph_key.y;
    let nonce_u128 = u64_to_u128_be(nonce);
    preimage[2] = &nonce_u128;
    for (i, c) in ciphertext.iter().enumerate() {
        preimage[3 + i] = c;
    }
    let msg_hash = poseidon(&preimage).map_err(|_| AnonVoteError::Poseidon)?;

    if let Some(msg_hash_from_relayer) = msg_hash_from_relayer {
        require!(
            msg_hash == msg_hash_from_relayer,
            AnonVoteError::RelayerMsgHashMismatch
        );
    }

    let proof = proof
        .decompress()
        .map_err(|_| AnonVoteError::ProofDecompressionError)?;
    let public_inputs = [
        msg_hash,
        relayer_ciphertext_hash,
        poll.census_root,
        u64_to_u128_be(poll.id),
        u8_to_u128_be(poll.n_choices),
        poll.coordinator_key.x,
        poll.coordinator_key.y,
        relayer_decrypt_key.x,
        relayer_decrypt_key.y,
    ];
    let mut v = Groth16Verifier::<9>::new(&proof.a, &proof.b, &proof.c, &public_inputs, &VK_VOTE)
        .map_err(|_| AnonVoteError::InvalidProof)?;
    v.verify().map_err(|_| AnonVoteError::InvalidProof)?;

    poll.running_msg_hash =
        poseidon(&[&poll.running_msg_hash, &msg_hash]).map_err(|_| AnonVoteError::Poseidon)?;

    emit!(VoteEvent {
        eph_key,
        nonce,
        ciphertext
    });

    Ok(())
}

#[derive(Accounts)]
pub struct VoteCommon<'info> {
    platform_config: Account<'info, PlatformConfig>,
    #[account(mut)]
    poll: Account<'info, Poll>,
    /// CHECK: the address is checked
    #[account(mut, address = platform_config.fee_destination)]
    platform_fee_destination: AccountInfo<'info>,
}
