use anchor_lang::prelude::*;

#[error_code]
pub enum ZkRelayerError {
    /// 6000 0x1770
    #[msg("Proof verification failed")]
    InvalidProof,
    /// 6001 0x1771
    #[msg("Poseidon hash calculation error")]
    Poseidon,
    /// 6002 0x1772
    #[msg("Relayer is not allowed")]
    RelayerNotAllowed,
    /// 6003 0x1773
    #[msg("Relayer did not receive the required fee")]
    RelayerNotFunded,
    /// 6004 0x1774
    #[msg("Failed to decompress proof")]
    ProofDecompressionError,
    /// 6005 0x1775
    #[msg("Target program is not allowed")]
    ProgramNotAllowed,
}
