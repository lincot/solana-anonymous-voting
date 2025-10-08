use anchor_lang::prelude::*;
use solana_bn254::compression::prelude::*;

/// Global fee collection config.
#[account(discriminator = 1u8)]
#[derive(Debug, InitSpace)]
pub struct PlatformConfig {
    pub admin: Pubkey,
    pub fee_destination: Pubkey,
    pub fee: u64,
}

/// Poll configuration and results. Also acts as a deposit to fund relayers
#[account(discriminator = 2u8)]
#[derive(Debug, InitSpace)]
pub struct Poll {
    pub id: u64,
    pub n_choices: u8,
    pub coordinator_key: Point,
    pub census_root: [u8; 32],
    pub running_msg_hash: [u8; 32],
    pub voting_start_time: u64,
    pub voting_end_time: u64,
    pub platform_fee: u64,
    pub fee: u64,
    pub fee_destination: Pubkey,
    /// URL containing name, description and names of options.
    #[max_len(0)]
    pub description_url: String,
    #[max_len(0)]
    pub census_url: String,
    /// The poll result, non-empty when tallied.
    #[max_len(0)]
    pub tally: Vec<u64>,
}

impl Poll {
    pub const fn added_space(
        n_choices: u8,
        description_url_len: usize,
        census_len_url: usize,
    ) -> usize {
        8 * n_choices as usize + description_url_len + census_len_url
    }
}

#[derive(Debug, AnchorSerialize, AnchorDeserialize)]
pub struct Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

#[derive(Debug, AnchorSerialize, AnchorDeserialize)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl CompressedProof {
    pub fn decompress(&self) -> core::result::Result<Proof, AltBn128CompressionError> {
        Ok(Proof {
            a: alt_bn128_g1_decompress(&self.a)?,
            b: alt_bn128_g2_decompress(&self.b)?,
            c: alt_bn128_g1_decompress(&self.c)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, AnchorSerialize, AnchorDeserialize, InitSpace)]
pub struct Point {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[account(discriminator = 3u8)]
#[derive(Debug, InitSpace)]
pub struct Tally {
    pub tally_hash: [u8; 32],
    pub running_msg_hash: [u8; 32],
    pub root: [u8; 32],
}
