/// Unlocking of "pay to public key hash" script pattern
struct P2PKHUnlock {
    /// Public key of owner of funds
    public_key: Vec<u8>,
    /// Signature verifying owner of funds
    signature: Vec<u8>,
}

/// Locking performed by "pay to public key hash" script pattern
struct P2PKHLock {
    /// Public key of transaction recipient
    public_key: Vec<u8>,
}

/// Transaction input
pub(crate) struct Input {
    /// ID of transaction to spend from
    transaction_id: Vec<u8>,
    /// Index of output of transaction to spend from
    output_index: u32,
    /// Data required for unlocking transaction
    unlock_mechanism: P2PKHUnlock,
    /// Sequence number of transaction
    sequence: u32,
}

/// Transaction output
pub(crate) struct Output {
    /// Value of output in "satoshis"
    amount: u64,
    /// Data to be provided to unlock transaction
    lock_mechanism: P2PKHLock,
}
