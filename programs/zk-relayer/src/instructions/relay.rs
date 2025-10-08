use anchor_lang::{prelude::*, solana_program::instruction::Instruction};
use groth16_solana::groth16::Groth16Verifier;
use solana_invoke::invoke_signed;

use crate::{error::*, state::*, utils::u64_to_u128_be, vk::VK_RELAY, ALLOWED_PROGRAMS};

#[derive(Accounts)]
#[instruction(state_id: u64)]
pub struct Relay<'info> {
    #[account(mut, address = relayer_config.relayer.fee_key)]
    relayer: Signer<'info>,
    relayer_config: Account<'info, ZkRelayerConfig>,
    #[account(
        seeds = [&b"RELAYER_STATE"[..], &target_program.key.to_bytes(), &state_id.to_le_bytes()],
        bump,
    )]
    relayer_state: Account<'info, RelayerState>,
    /// CHECK: it's one of the allowed programs
    #[account(
        constraint = ALLOWED_PROGRAMS.contains(target_program.key)
            @ ZkRelayerError::ProgramNotAllowed
    )]
    target_program: AccountInfo<'info>,
    system_program: Program<'info, System>,
}

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
    let relayer = &ctx.accounts.relayer;
    let relayer_config = &mut ctx.accounts.relayer_config;
    let relayer_state = &mut ctx.accounts.relayer_state;
    let target_program = &ctx.accounts.target_program;

    let decryption_key = &relayer_config.relayer.decryption_key;

    let proof = proof
        .decompress()
        .map_err(|_| ZkRelayerError::ProofDecompressionError)?;
    let public_inputs = [
        root_after,
        ciphertext_hash,
        relayer_state.root,
        msg_hash,
        u64_to_u128_be(relayer_state.msg_limit),
        eph_key.x,
        eph_key.y,
        u64_to_u128_be(nonce),
    ];
    let mut v = Groth16Verifier::<8>::new(&proof.a, &proof.b, &proof.c, &public_inputs, &VK_RELAY)
        .map_err(|_| ZkRelayerError::InvalidProof)?;
    v.verify().map_err(|_| ZkRelayerError::InvalidProof)?;

    relayer_state.root = root_after;

    let mut full_data =
        Vec::with_capacity(1 + 2 * 32 + 8 + ciphertext_hash.len() + 32 + 2 * 32 + data.len());
    full_data.push(discriminator);
    full_data.extend(&eph_key.x);
    full_data.extend(&eph_key.y);
    full_data.extend(&nonce.to_le_bytes());
    full_data.extend(&ciphertext_hash);
    full_data.extend(&msg_hash);
    full_data.extend(&decryption_key.x);
    full_data.extend(&decryption_key.y);
    full_data.extend(&data);

    let mut metas = Vec::with_capacity(2 + ctx.remaining_accounts.len());
    metas.push(AccountMeta {
        pubkey: relayer.key(),
        is_signer: true,
        is_writable: true,
    });
    // relayer_state as signer to assert that caller is zk-relayer
    metas.push(AccountMeta {
        pubkey: relayer_state.key(),
        is_signer: true,
        is_writable: false,
    });
    metas.extend(ctx.remaining_accounts.iter().map(|account| AccountMeta {
        pubkey: account.key(),
        is_signer: account.is_signer,
        is_writable: account.is_writable,
    }));

    let mut accounts = Vec::with_capacity(2 + ctx.remaining_accounts.len());
    accounts.push(relayer.to_account_info());
    accounts.push(relayer_state.to_account_info());
    accounts.extend(ctx.remaining_accounts.iter().cloned());

    let balance_before = relayer.get_lamports();

    let ix = Instruction::new_with_bytes(ctx.accounts.target_program.key(), &full_data, metas);
    invoke_signed(
        &ix,
        &accounts,
        &[&[
            &b"RELAYER_STATE"[..],
            &target_program.key.to_bytes(),
            &state_id.to_le_bytes(),
            &[ctx.bumps.relayer_state],
        ]],
    )?;

    let balance_after = relayer.get_lamports();

    require!(
        balance_after > balance_before && balance_after - balance_before >= relayer_state.fee,
        ZkRelayerError::RelayerNotFunded
    );

    Ok(())
}
