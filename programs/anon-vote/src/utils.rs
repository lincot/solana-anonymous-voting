use anchor_lang::prelude::*;
use solana_invoke::invoke;
use solana_poseidon::PoseidonSyscallError;

pub fn system_transfer<'info>(
    from: AccountInfo<'info>,
    to: AccountInfo<'info>,
    lamports: u64,
) -> Result<()> {
    invoke(
        &solana_system_interface::instruction::transfer(&from.key(), &to.key(), lamports),
        &[from, to],
    )?;
    Ok(())
}

pub fn transfer(from: &AccountInfo, to: &AccountInfo, lamports: u64) -> Result<()> {
    **from.try_borrow_mut_lamports()? = (from.lamports())
        .checked_sub(lamports)
        .ok_or(ProgramError::InsufficientFunds)?;
    **to.try_borrow_mut_lamports()? += lamports;
    Ok(())
}

pub fn u8_to_u128_be(x: u8) -> [u8; 32] {
    let mut res = [0; 32];
    res[31] = x;
    res
}

pub fn u64_to_u128_be(x: u64) -> [u8; 32] {
    let mut res = [0; 32];
    res[32 - 8..].copy_from_slice(&x.to_be_bytes());
    res
}

/// Poseidon hash a [maximum of 12 elements](https://github.com/anza-xyz/agave/blob/4a35485d867e8b6d896e8e1ef91e165839f652ed/syscalls/src/lib.rs#L1718).
pub fn poseidon(inputs: &[&[u8]]) -> core::result::Result<[u8; 32], PoseidonSyscallError> {
    solana_poseidon::hashv(
        solana_poseidon::Parameters::Bn254X5,
        solana_poseidon::Endianness::BigEndian,
        inputs,
    )
    .map(|x| x.0)
}
