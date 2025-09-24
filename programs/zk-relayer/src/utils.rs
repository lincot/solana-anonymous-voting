use anchor_lang::prelude::*;
use solana_invoke::invoke;

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

pub fn u64_to_u128_be(x: u64) -> [u8; 32] {
    let mut res = [0; 32];
    res[32 - 8..].copy_from_slice(&x.to_be_bytes());
    res
}
