const SHA256_OUT_SIZE: u8 = 32;
const ECDSA_SIG_SIZE: u8 = 64;
const TRANSACTION_ID_SIZE: u8 = 32;

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

impl Input {
    fn serialise(&self) -> Vec<u8> {
        let mut data = vec![
            0;
            TRANSACTION_ID_SIZE as usize
                + u32::BITS as usize / 8
                + Input::SCRIPT_SIG_SIZE as usize
                + u32::BITS as usize / 8
        ];
        data[..TRANSACTION_ID_SIZE as usize].copy_from_slice(&self.transaction_id);
        data[TRANSACTION_ID_SIZE as usize..TRANSACTION_ID_SIZE as usize + u32::BITS as usize / 8]
            .copy_from_slice(&self.output_index.to_le_bytes());
        data[TRANSACTION_ID_SIZE as usize + u32::BITS as usize / 8
            ..TRANSACTION_ID_SIZE as usize
                + u32::BITS as usize / 8
                + Input::SCRIPT_SIG_SIZE as usize]
            .copy_from_slice(&self.script_sig);
        data[TRANSACTION_ID_SIZE as usize
            + u32::BITS as usize / 8
            + Input::SCRIPT_SIG_SIZE as usize..]
            .copy_from_slice(&self.sequence.to_le_bytes());
        data
    }
}

/// Transaction output
///
/// Note: Assume the use of "pay to public key hash" (P2PKH) script pattern
pub(crate) struct Output {
    /// Value of output in "satoshis"
    amount: u64,
    /// Data to be provided to unlock transaction
    ///
    /// Note: From P2PKH assumption, this contains just the SHA256 hash of the public key of the
    /// recipient
    script_pub_key: Vec<u8>,
}

impl Output {
    /// Size of `script_pub_key` field
    ///
    /// Note: Assuming `P2PKH` script pattern means that the length is always the same and is thus
    /// compile-time known for every instance of [`Output`]
    const SCRIPT_PUB_KEY_SIZE: u8 = SHA256_OUT_SIZE;
}

impl Output {
    fn serialise(&self) -> Vec<u8> {
        let mut data = vec![0; u64::BITS as usize / 8 + SHA256_OUT_SIZE as usize];
        data[..u64::BITS as usize / 8].copy_from_slice(&self.amount.to_le_bytes());
        data[u64::BITS as usize / 8..].copy_from_slice(&self.script_pub_key);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::{Input, Output};

    #[test]
    fn serialise_output() {
        let amount = 123;
        let mut script_pub_key = (0..32).collect::<Vec<_>>();
        let output = Output {
            amount,
            script_pub_key: script_pub_key.clone(),
        };
        let mut expected_serialised_data = Vec::new();
        expected_serialised_data.append(&mut amount.to_le_bytes().to_vec());
        expected_serialised_data.append(&mut script_pub_key);
        let serialised_data = output.serialise();
        assert_eq!(serialised_data, expected_serialised_data);
    }

    #[test]
    fn serialise_input() {
        let mut transaction_id = (0..32).collect::<Vec<_>>();
        let output_index = 1;
        let mut script_sig = (0..96).collect::<Vec<_>>();
        let sequence = 0xFDFFFFFF;
        let input = Input {
            transaction_id: transaction_id.clone(),
            output_index,
            script_sig: script_sig.clone(),
            sequence,
        };
        let mut expected_serialised_data = Vec::new();
        expected_serialised_data.append(&mut transaction_id);
        expected_serialised_data.append(&mut output_index.to_le_bytes().to_vec());
        expected_serialised_data.append(&mut script_sig);
        expected_serialised_data.append(&mut sequence.to_le_bytes().to_vec());
        let serialised_data = input.serialise();
        assert_eq!(serialised_data, expected_serialised_data);
    }
}
