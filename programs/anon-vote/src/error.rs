use anchor_lang::prelude::*;

#[error_code]
pub enum AnonVoteError {
    /// 6000 0x1770
    #[msg("Proof verification failed")]
    InvalidProof,
    /// 6001 0x1771
    #[msg("Poseidon hash calculation error")]
    Poseidon,
    /// 6002 0x1772
    #[msg("Tally wasn't calculated correctly")]
    IncorrectTally,
    /// 6003 0x1773
    #[msg("Operation not allowed during that time")]
    BadTime,
    /// 6004 0x1774
    #[msg("Failed to decompress proof")]
    ProofDecompressionError,
    /// 6005 0x1775
    #[msg("Relayer message hash mismatch")]
    RelayerMsgHashMismatch,
    /// 6006 0x1776
    #[msg("Poll duration is too long")]
    PollTooLong,
}
