const SHA256_OUT_SIZE: u8 = 32;
const ECDSA_SIG_SIZE: u8 = 64;

/// Locking performed by "pay to public key hash" script pattern
struct P2PKHLock {
    /// Public key of transaction recipient
    public_key: Vec<u8>,
}

/// Transaction input
///
/// Note: Assume the use of "pay to public key hash" (P2PKH) script pattern and uncompressed ECDSA
/// keys
pub(crate) struct Input {
    /// ID of transaction to spend from
    transaction_id: Vec<u8>,
    /// Index of output of transaction to spend from
    output_index: u32,
    /// Data for unlocking referenced transaction
    ///
    /// Note: From P2PKH and ECDSA key assumption, plus not including things related to the Script
    /// language, this contains just the SHA256 hash of the public key of the owner of the
    /// referenced transaction, and the ECDSA signature of the transaction which is using this
    /// input
    script_sig: Vec<u8>,
    /// Sequence number of transaction
    sequence: u32,
}

impl Input {
    /// Size of `script_sig` field
    ///
    /// Note: Assuming `P2PKH` script pattern and ECDSA signature means that the length is always
    /// the same and is thus compile-time known for every instance of [`Input`]
    const SCRIPT_SIG_SIZE: u8 = SHA256_OUT_SIZE + ECDSA_SIG_SIZE;
}

/// Transaction output
pub(crate) struct Output {
    /// Value of output in "satoshis"
    amount: u64,
    /// Data to be provided to unlock transaction
    lock_mechanism: P2PKHLock,
}
