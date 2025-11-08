use anchor_lang::prelude::*;
use solana_bn254::compression::prelude::*;

#[account(discriminator = 250u8)]
#[derive(Debug, InitSpace)]
pub struct ZkRelayerConfig {
    pub admin: Pubkey,
    pub fee: u64,
    pub relayer: Relayer,
}

impl ZkRelayerConfig {
    pub fn added_space(relayer_endpoint_len: usize) -> usize {
        Relayer::INIT_SPACE + relayer_endpoint_len
    }
}

#[derive(Clone, Debug, AnchorSerialize, AnchorDeserialize, InitSpace)]
pub struct Relayer {
    #[max_len(0)]
    pub endpoint: String,
    pub fee_key: Pubkey,
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

#[derive(Clone, Debug, AnchorSerialize, AnchorDeserialize, InitSpace)]
pub struct Point {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// State per target program event, such as a poll.
#[account(discriminator = 251u8)]
#[derive(Debug, InitSpace)]
pub struct RelayerState {
    pub root: [u8; 32],
    /// Fee fixed at the time of creation.
    pub fee: u64,
    /// Message limit per user.
    pub msg_limit: u64,
    pub end_time: u64,
}
