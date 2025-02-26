/// Transaction input
pub(crate) struct Input {
    /// ID of transaction to spend from
    transaction_id: Vec<u8>,
    /// Index of output of transaction to spend from
    output_index: u32,
    /// Size of variable-sized script
    script_size: u32,
    /// Script used to spend from given input
    script: Vec<u8>,
    /// Sequence number of transaction
    sequence: u32,
}

/// Transaction output
pub(crate) struct Output {
    /// Value of output in "satoshis"
    amount: u64,
    /// Size of variable-sized public key script
    pub_key_script_size: u32,
    /// Locking script
    pub_key_script: Vec<u8>,
}
