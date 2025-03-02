const SHA256_OUT_SIZE: u8 = 32;
const ECDSA_SIG_SIZE: u8 = 64;
const TRANSACTION_ID_SIZE: u8 = 32;
const SERIALISED_INPUT_SIZE: u8 =
    TRANSACTION_ID_SIZE + 4 + SHA256_OUT_SIZE + ECDSA_SIG_SIZE + 1 + 4;
const U32_SIZE: usize = u32::BITS as usize / 8;
const U64_SIZE: usize = u64::BITS as usize / 8;

/// Transaction input
///
/// Note: Assume the use of "pay to public key hash" (P2PKH) script pattern and uncompressed ECDSA
/// keys
#[derive(Clone)]
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
        let mut data =
            vec![0; TRANSACTION_ID_SIZE as usize + U32_SIZE + self.script_sig.len() + U32_SIZE];
        data[..TRANSACTION_ID_SIZE as usize].copy_from_slice(&self.transaction_id);
        data[TRANSACTION_ID_SIZE as usize..TRANSACTION_ID_SIZE as usize + U32_SIZE]
            .copy_from_slice(&self.output_index.to_le_bytes());
        data[TRANSACTION_ID_SIZE as usize + U32_SIZE
            ..TRANSACTION_ID_SIZE as usize + U32_SIZE + self.script_sig.len()]
            .copy_from_slice(&self.script_sig);
        data[TRANSACTION_ID_SIZE as usize + U32_SIZE + self.script_sig.len()..]
            .copy_from_slice(&self.sequence.to_le_bytes());
        data
    }
}

/// Transaction output
///
/// Note: Assume the use of "pay to public key hash" (P2PKH) script pattern
#[derive(Clone)]
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
        let mut data = vec![0; U64_SIZE + SHA256_OUT_SIZE as usize];
        data[..U64_SIZE].copy_from_slice(&self.amount.to_le_bytes());
        data[U64_SIZE..].copy_from_slice(&self.script_pub_key);
        data
    }
}

/// Signifies which parts of a transaction have been signed
#[derive(Clone, Copy)]
pub(crate) enum SigHashType {
    /// All inputs and all outputs
    All,
}

impl SigHashType {
    /// Serialise sig hash type for appending to transaction data (4 bytes, in litte-endian order)
    fn serialise_for_transaction(&self) -> [u8; 4] {
        match self {
            SigHashType::All => u32::to_le_bytes(1),
        }
    }

    /// Serialise sig hash type for appending to signature data (1 byte)
    fn serialise_for_signature(&self) -> u8 {
        match self {
            SigHashType::All => 1,
        }
    }
}

/// Take funds from previously existing transaction(s) as input(s) and package in output(s) which
/// can be accessed by intended recipient(s)
pub(crate) struct Transaction {
    /// Version number of transaction
    version: u32,
    /// Inputs used for transaction
    inputs: Vec<Input>,
    /// Outputs produced by transaction
    outputs: Vec<Output>,
    /// Time/block height after which the transaction can be collected into a block
    locktime: u32,
    /// Type of signature hash for transaction
    sig_hash_type: SigHashType,
}

impl Transaction {
    /// Generate iterator over data to sign to unlock each input
    fn inputs_for_signing(
        &mut self,
        output_pub_key_hashes: Vec<Vec<u8>>,
    ) -> impl Iterator<Item = Vec<u8>> + '_ {
        std::iter::zip(self.inputs.iter(), output_pub_key_hashes).map(
            |(input, mut referenced_output)| {
                let mut input_with_placeholder_script_sig = input.clone();
                input_with_placeholder_script_sig
                    .script_sig
                    .append(&mut referenced_output);

                let mut unsigned_transaction_serialised = Vec::new();
                unsigned_transaction_serialised
                    .append(&mut u32::to_le_bytes(self.version).to_vec());
                unsigned_transaction_serialised.push(self.inputs.len() as u8);
                unsigned_transaction_serialised
                    .append(&mut input_with_placeholder_script_sig.serialise());
                unsigned_transaction_serialised.push(self.outputs.len() as u8);
                unsigned_transaction_serialised.append(&mut self.outputs[0].serialise());
                unsigned_transaction_serialised
                    .append(&mut u32::to_le_bytes(self.locktime).to_vec());
                unsigned_transaction_serialised
                    .append(&mut self.sig_hash_type.serialise_for_transaction().to_vec());

                ring::digest::digest(&ring::digest::SHA256, &unsigned_transaction_serialised)
                    .as_ref()
                    .to_vec()
            },
        )
    }

    /// Provide signatures to unlock all inputs
    fn sign(&mut self, signatures: Vec<Vec<u8>>, referenced_outputs: &[Vec<u8>]) {
        for ((input, signature), referenced_output) in
            std::iter::zip(self.inputs.iter_mut(), signatures.into_iter()).zip(referenced_outputs)
        {
            let mut new_script_sig = [0; SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize + 1];
            new_script_sig[..SHA256_OUT_SIZE as usize].copy_from_slice(referenced_output);
            new_script_sig
                [SHA256_OUT_SIZE as usize..SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize]
                .copy_from_slice(signature.as_ref());
            new_script_sig[new_script_sig.len() - 1] = self.sig_hash_type.serialise_for_signature();
            input.script_sig = new_script_sig.to_vec();
        }
    }

    /// Serialise signed transaction data
    fn serialise(&self) -> Vec<u8> {
        let mut data = vec![
            0;
            U32_SIZE
                + 1
                + SERIALISED_INPUT_SIZE as usize * self.inputs.len()
                + 1
                + U64_SIZE
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
        ];
        data[..U32_SIZE].copy_from_slice(&self.version.to_le_bytes());
        data[U32_SIZE] = self.inputs.len() as u8;

        for (idx, input) in self.inputs.iter().enumerate() {
            let serialised_signed_input = input.serialise();
            data[U32_SIZE + 1 + idx * SERIALISED_INPUT_SIZE as usize
                ..U32_SIZE
                    + 1
                    + idx * SERIALISED_INPUT_SIZE as usize
                    + serialised_signed_input.len()]
                .copy_from_slice(&serialised_signed_input);
        }

        data[U32_SIZE + 1 + SERIALISED_INPUT_SIZE as usize * self.inputs.len()] =
            self.outputs.len() as u8;
        let serialised_output = self.outputs[0].serialise();
        data[U32_SIZE + 1 + SERIALISED_INPUT_SIZE as usize * self.inputs.len() + 1
            ..U32_SIZE
                + 1
                + SERIALISED_INPUT_SIZE as usize * self.inputs.len()
                + 1
                + serialised_output.len()]
            .copy_from_slice(&serialised_output);
        data[U32_SIZE
            + 1
            + SERIALISED_INPUT_SIZE as usize * self.inputs.len()
            + 1
            + serialised_output.len()..]
            .copy_from_slice(&u32::to_le_bytes(self.locktime));
        data
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Input, Output, SigHashType, Transaction, ECDSA_SIG_SIZE, SHA256_OUT_SIZE, U32_SIZE,
        U64_SIZE,
    };
    use ring::{
        rand,
        signature::{self, KeyPair, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING},
    };

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

    #[test]
    fn serialise_input_with_placeholder_script_sig() {
        let mut transaction_id = (0..32).collect::<Vec<_>>();
        let output_index = 1;
        let mut placeholder_script_sig = (2..34).collect::<Vec<_>>();
        let sequence = 0xFDFFFFFF;
        let input = Input {
            transaction_id: transaction_id.clone(),
            output_index,
            script_sig: placeholder_script_sig.clone(),
            sequence,
        };
        let mut expected_serialised_data = Vec::new();
        expected_serialised_data.append(&mut transaction_id);
        expected_serialised_data.append(&mut output_index.to_le_bytes().to_vec());
        expected_serialised_data.append(&mut placeholder_script_sig);
        expected_serialised_data.append(&mut sequence.to_le_bytes().to_vec());
        let serialised_data = input.serialise();
        assert_eq!(serialised_data, expected_serialised_data);
    }

    #[test]
    fn serialise_sig_hash_all_type_for_transaction_data() {
        let expected_serialised_data = u32::to_le_bytes(1);
        assert_eq!(
            SigHashType::All.serialise_for_transaction(),
            expected_serialised_data
        );
    }

    #[test]
    fn serialise_sig_hash_all_type_for_signature_data() {
        let expected_serialised_data = 1;
        assert_eq!(
            SigHashType::All.serialise_for_signature(),
            expected_serialised_data
        );
    }

    #[test]
    fn sign_transaction_with_one_input_one_output() {
        let amount = 123;
        let script_pub_key_hash = (0..32).collect::<Vec<_>>();
        let outputs = vec![Output {
            amount,
            script_pub_key: script_pub_key_hash.clone(),
        }];

        let transaction_id = (0..32).collect::<Vec<_>>();
        let output_index = 1;
        let sequence = 0xFDFFFFFF;
        let mut inputs = vec![Input {
            transaction_id: transaction_id.clone(),
            output_index,
            script_sig: Vec::new(),
            sequence,
        }];

        let version = 1;
        let locktime = 0;
        let sig_hash_type = SigHashType::All;
        let mut transaction = Transaction {
            version,
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            locktime,
            sig_hash_type,
        };

        let referenced_script_pub_key_hash = (2..34).collect::<Vec<_>>();
        let mut input_with_placeholder_script_sig = inputs[0].clone();
        input_with_placeholder_script_sig
            .script_sig
            .clone_from(&referenced_script_pub_key_hash);

        // Form serialised version of transaction with placeholder script sig
        let mut unsigned_transaction_serialised = Vec::new();
        unsigned_transaction_serialised.append(&mut u32::to_le_bytes(version).to_vec());
        unsigned_transaction_serialised.push(transaction.inputs.len() as u8);
        unsigned_transaction_serialised.append(&mut input_with_placeholder_script_sig.serialise());
        unsigned_transaction_serialised.push(transaction.outputs.len() as u8);
        unsigned_transaction_serialised.append(&mut outputs[0].serialise());
        unsigned_transaction_serialised.append(&mut u32::to_le_bytes(locktime).to_vec());
        unsigned_transaction_serialised
            .append(&mut sig_hash_type.serialise_for_transaction().to_vec());

        // Apply SHA256 once to serialised transaction data
        let sha256_hash =
            ring::digest::digest(&ring::digest::SHA256, &unsigned_transaction_serialised);

        // Create ECDSA signature based on hashed transaction data. The ECDSA signature creation
        // does a single SHA256 hash which, when applied to the already single hashed data,
        // achieves the double-hashing ("HASH256") required.
        //
        // NOTE: Not using DER-encoding for now to avoid variable length signature
        let rng = rand::SystemRandom::new();
        let ecdsa_bytes =
            signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            ecdsa_bytes.as_ref(),
            &rng,
        )
        .unwrap();
        let sig = key_pair.sign(&rng, sha256_hash.as_ref()).unwrap();

        // Put together public key hash, signature, and signature hash type
        let mut script_sig = [0; SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize + 1];
        script_sig[..SHA256_OUT_SIZE as usize].copy_from_slice(&referenced_script_pub_key_hash);
        script_sig[SHA256_OUT_SIZE as usize..SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize]
            .copy_from_slice(sig.as_ref());
        script_sig[script_sig.len() - 1] = transaction.sig_hash_type.serialise_for_signature();

        // Insert "unlocking script" into the `script_sig` field of the single input
        inputs[0].script_sig = script_sig.to_vec();

        // Form expected serialised transaction data with signed input
        let mut expected_serialised_data = [0; U32_SIZE
            + 1
            + SHA256_OUT_SIZE as usize
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            + ECDSA_SIG_SIZE as usize
            + 1
            + U32_SIZE
            + 1
            + U64_SIZE
            + SHA256_OUT_SIZE as usize
            + U32_SIZE];
        expected_serialised_data[..U32_SIZE].copy_from_slice(&transaction.version.to_le_bytes());
        expected_serialised_data[U32_SIZE] = inputs.len() as u8;
        let serialised_signed_input = inputs[0].serialise();
        expected_serialised_data[U32_SIZE + 1..U32_SIZE + 1 + serialised_signed_input.len()]
            .copy_from_slice(&serialised_signed_input);
        expected_serialised_data[U32_SIZE + 1 + serialised_signed_input.len()] =
            outputs.len() as u8;
        let serialised_output = outputs[0].serialise();
        expected_serialised_data[U32_SIZE + 1 + serialised_signed_input.len() + 1
            ..U32_SIZE + 1 + serialised_signed_input.len() + 1 + serialised_output.len()]
            .copy_from_slice(&serialised_output);
        expected_serialised_data
            [U32_SIZE + 1 + serialised_signed_input.len() + 1 + serialised_output.len()..]
            .copy_from_slice(&u32::to_le_bytes(locktime));

        // NOTE: For now, assume that the transaction signing method is provided the script pub key
        // info from the referenced outputs that its inputs refer to, though it would likely make
        // more sense for the transaction signing method to call the relevant function to do this
        // fetching of data.
        let referenced_outputs = [referenced_script_pub_key_hash];

        // Sign transaction by signing the single input
        let mut input_data_being_signed = Vec::new();
        let input_signatures = transaction
            .inputs_for_signing(referenced_outputs.to_vec())
            .map(|data| {
                // Store for later use when asserting that the signature can be successfully
                // verified
                input_data_being_signed.append(&mut data.clone());
                key_pair.sign(&rng, &data).unwrap().as_ref().to_vec()
            })
            .collect::<Vec<_>>();
        transaction.sign(input_signatures, &referenced_outputs);
        let signed_transaction_data = transaction.serialise();

        // Can't directly compare `signed_transaction_data` and `expected_serialised_data` due to
        // different nonce being used when creating the signature for the two cases.
        //
        // Perhaps there are better ways, but for some level of verification that the
        // implementation did was what intended, can:
        // - check all parts of the two that are not the signature
        // - extract the signature from `signed_transaction_data` and attempt to verify it

        // Assert equality of the parts of `signed_transaction_data` and `expected_serialised_data`
        // that aren't the signature
        assert_eq!(
            signed_transaction_data
                [..U32_SIZE + 1 + SHA256_OUT_SIZE as usize + U32_SIZE + SHA256_OUT_SIZE as usize],
            expected_serialised_data
                [..U32_SIZE + 1 + SHA256_OUT_SIZE as usize + U32_SIZE + SHA256_OUT_SIZE as usize]
        );
        assert_eq!(
            signed_transaction_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize..],
            expected_serialised_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize..]
        );

        // Check that the signature portion of `signed_transaction_data` is successfully verified
        // with the public key that was used to sign the transaction data
        let sig_in_serialised_transaction = &signed_transaction_data[U32_SIZE
            + 1
            + SHA256_OUT_SIZE as usize
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            ..U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize];
        let pub_key = signature::UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_FIXED,
            key_pair.public_key().as_ref(),
        );
        let res = pub_key.verify(&input_data_being_signed, sig_in_serialised_transaction);
        assert!(res.is_ok());
    }

    #[test]
    fn sign_transaction_with_two_inputs_one_output() {
        let amount = 123;
        let script_pub_key_hash = (0..32).collect::<Vec<_>>();
        let outputs = vec![Output {
            amount,
            script_pub_key: script_pub_key_hash.clone(),
        }];

        let input_one_txid = (0..32).collect::<Vec<_>>();
        let input_one_output_index = 1;
        let input_two_txid = (1..33).collect::<Vec<_>>();
        let input_two_output_index = 0;
        let sequence = 0xFDFFFFFF;
        let mut inputs = vec![
            Input {
                transaction_id: input_one_txid.clone(),
                output_index: input_one_output_index,
                script_sig: Vec::new(),
                sequence,
            },
            Input {
                transaction_id: input_two_txid.clone(),
                output_index: input_two_output_index,
                script_sig: Vec::new(),
                sequence,
            },
        ];

        let version = 1;
        let locktime = 0;
        let sig_hash_type = SigHashType::All;
        let mut transaction = Transaction {
            version,
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            locktime,
            sig_hash_type,
        };

        let input_one_referenced_script_pub_key_hash = (2..34).collect::<Vec<_>>();
        let mut input_one_with_placeholder_script_sig = inputs[0].clone();
        input_one_with_placeholder_script_sig
            .script_sig
            .clone_from(&input_one_referenced_script_pub_key_hash);
        let input_two_referenced_script_pub_key_hash = (5..37).collect::<Vec<_>>();
        let mut input_two_with_placeholder_script_sig = inputs[1].clone();
        input_two_with_placeholder_script_sig
            .script_sig
            .clone_from(&input_two_referenced_script_pub_key_hash);

        // Generate ECDSA keypair
        let rng = rand::SystemRandom::new();
        let ecdsa_bytes =
            signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            ecdsa_bytes.as_ref(),
            &rng,
        )
        .unwrap();

        // Form serialised version of final signed transaction

        // To create a signature for the first input, form serialised version of transaction with:
        // - placeholder script sig for input one
        // - empty script sig for input two
        let mut unsigned_transaction_serialised_for_input_one = Vec::new();
        unsigned_transaction_serialised_for_input_one
            .append(&mut u32::to_le_bytes(version).to_vec());
        unsigned_transaction_serialised_for_input_one.push(transaction.inputs.len() as u8);
        unsigned_transaction_serialised_for_input_one
            .append(&mut input_one_with_placeholder_script_sig.serialise());
        unsigned_transaction_serialised_for_input_one.append(&mut inputs[1].serialise());
        unsigned_transaction_serialised_for_input_one.push(transaction.outputs.len() as u8);
        unsigned_transaction_serialised_for_input_one.append(&mut outputs[0].serialise());
        unsigned_transaction_serialised_for_input_one
            .append(&mut u32::to_le_bytes(locktime).to_vec());
        unsigned_transaction_serialised_for_input_one
            .append(&mut sig_hash_type.serialise_for_transaction().to_vec());
        let sha256_hash = ring::digest::digest(
            &ring::digest::SHA256,
            &unsigned_transaction_serialised_for_input_one,
        );
        let input_one_sig = key_pair.sign(&rng, sha256_hash.as_ref()).unwrap();
        let mut input_one_script_sig = [0; SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize + 1];
        input_one_script_sig[..SHA256_OUT_SIZE as usize]
            .copy_from_slice(&input_one_referenced_script_pub_key_hash);
        input_one_script_sig
            [SHA256_OUT_SIZE as usize..SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize]
            .copy_from_slice(input_one_sig.as_ref());
        input_one_script_sig[input_one_script_sig.len() - 1] =
            transaction.sig_hash_type.serialise_for_signature();
        inputs[0].script_sig = input_one_script_sig.to_vec();

        // To create a signature for the second input, form serialised version of transaction with:
        // - empty script sig for input one
        // - placeholder script sig for input two
        let mut unsigned_transaction_serialised_for_input_two = Vec::new();
        unsigned_transaction_serialised_for_input_two
            .append(&mut u32::to_le_bytes(version).to_vec());
        unsigned_transaction_serialised_for_input_two.push(transaction.inputs.len() as u8);
        unsigned_transaction_serialised_for_input_two.append(&mut inputs[0].serialise());
        unsigned_transaction_serialised_for_input_two
            .append(&mut input_two_with_placeholder_script_sig.serialise());
        unsigned_transaction_serialised_for_input_two.push(transaction.outputs.len() as u8);
        unsigned_transaction_serialised_for_input_two.append(&mut outputs[0].serialise());
        unsigned_transaction_serialised_for_input_two
            .append(&mut u32::to_le_bytes(locktime).to_vec());
        unsigned_transaction_serialised_for_input_two
            .append(&mut sig_hash_type.serialise_for_transaction().to_vec());
        let sha256_hash = ring::digest::digest(
            &ring::digest::SHA256,
            &unsigned_transaction_serialised_for_input_two,
        );
        let input_two_sig = key_pair.sign(&rng, sha256_hash.as_ref()).unwrap();
        let mut input_two_script_sig = [0; SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize + 1];
        input_two_script_sig[..SHA256_OUT_SIZE as usize]
            .copy_from_slice(&input_two_referenced_script_pub_key_hash);
        input_two_script_sig
            [SHA256_OUT_SIZE as usize..SHA256_OUT_SIZE as usize + ECDSA_SIG_SIZE as usize]
            .copy_from_slice(input_two_sig.as_ref());
        input_two_script_sig[input_two_script_sig.len() - 1] =
            transaction.sig_hash_type.serialise_for_signature();
        inputs[1].script_sig = input_two_script_sig.to_vec();

        // Form expected serialised transaction data with both signed inputs
        let mut expected_serialised_data = [0; U32_SIZE
            + 1                         // start of inputs
            + SHA256_OUT_SIZE as usize  // start of input one
            + U32_SIZE
            + SHA256_OUT_SIZE as usize  // start of input one sig
            + ECDSA_SIG_SIZE as usize
            + 1
            + U32_SIZE
            + SHA256_OUT_SIZE as usize  // start of input two
            + U32_SIZE
            + SHA256_OUT_SIZE as usize  // start of input two sig
            + ECDSA_SIG_SIZE as usize
            + 1
            + U32_SIZE
            + 1                         // start of outputs
            + U64_SIZE
            + SHA256_OUT_SIZE as usize
            + U32_SIZE];
        expected_serialised_data[..U32_SIZE].copy_from_slice(&transaction.version.to_le_bytes());
        expected_serialised_data[U32_SIZE] = inputs.len() as u8;
        let serialised_signed_input_one = inputs[0].serialise();
        expected_serialised_data[U32_SIZE + 1..U32_SIZE + 1 + serialised_signed_input_one.len()]
            .copy_from_slice(&serialised_signed_input_one);
        let serialised_signed_input_two = inputs[1].serialise();
        expected_serialised_data[U32_SIZE + 1 + serialised_signed_input_one.len()
            ..U32_SIZE + 1 + serialised_signed_input_one.len() + serialised_signed_input_two.len()]
            .copy_from_slice(&serialised_signed_input_two);
        expected_serialised_data[U32_SIZE
            + 1
            + serialised_signed_input_one.len()
            + serialised_signed_input_two.len()] = outputs.len() as u8;
        let serialised_output = outputs[0].serialise();
        expected_serialised_data[U32_SIZE
            + 1
            + serialised_signed_input_one.len()
            + serialised_signed_input_two.len()
            + 1
            ..U32_SIZE
                + 1
                + serialised_signed_input_one.len()
                + serialised_signed_input_two.len()
                + 1
                + serialised_output.len()]
            .copy_from_slice(&serialised_output);
        expected_serialised_data[U32_SIZE
            + 1
            + serialised_signed_input_one.len()
            + serialised_signed_input_two.len()
            + 1
            + serialised_output.len()..]
            .copy_from_slice(&u32::to_le_bytes(locktime));

        // Sign transaction by signing both inputs
        let referenced_outputs = [
            input_one_referenced_script_pub_key_hash,
            input_two_referenced_script_pub_key_hash,
        ];
        let mut input_data_being_signed = Vec::new();
        let input_signatures = transaction
            .inputs_for_signing(referenced_outputs.to_vec())
            .map(|data| {
                // Store for later use when asserting that the signatures can be successfully
                // verified
                input_data_being_signed.push(data.clone());
                key_pair.sign(&rng, &data).unwrap().as_ref().to_vec()
            })
            .collect::<Vec<_>>();
        transaction.sign(input_signatures, &referenced_outputs);
        let signed_transaction_data = transaction.serialise();

        // Assert equality of the parts of `signed_transaction_data` and `expected_serialised_data`
        // that aren't the signatures

        // Portion before the first input signature
        assert_eq!(
            signed_transaction_data
                [..U32_SIZE + 1 + SHA256_OUT_SIZE as usize + U32_SIZE + SHA256_OUT_SIZE as usize],
            expected_serialised_data
                [..U32_SIZE + 1 + SHA256_OUT_SIZE as usize + U32_SIZE + SHA256_OUT_SIZE as usize]
        );
        // Portion after the first input signature but before the second input signature
        assert_eq!(
            signed_transaction_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize
                ..U32_SIZE
                    + 1
                    + SHA256_OUT_SIZE as usize
                    + U32_SIZE
                    + SHA256_OUT_SIZE as usize
                    + ECDSA_SIG_SIZE as usize
                    + 1
                    + U32_SIZE
                    + SHA256_OUT_SIZE as usize
                    + U32_SIZE],
            expected_serialised_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize
                ..U32_SIZE
                    + 1
                    + SHA256_OUT_SIZE as usize
                    + U32_SIZE
                    + SHA256_OUT_SIZE as usize
                    + ECDSA_SIG_SIZE as usize
                    + 1
                    + U32_SIZE
                    + SHA256_OUT_SIZE as usize
                    + U32_SIZE]
        );
        // Portion after the second input signature
        assert_eq!(
            signed_transaction_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize  // start of input one
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize
                + 1
                + U32_SIZE
                + SHA256_OUT_SIZE as usize  // start of input two
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize..],
            expected_serialised_data[U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize
                + 1
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize..]
        );

        // Check that the signature portions in `signed_transaction_data` are successfully verified
        // with the public key that was used to sign the transaction data
        let pub_key = signature::UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_FIXED,
            key_pair.public_key().as_ref(),
        );
        let input_one_sig_in_serialised_transaction = &signed_transaction_data[u32::BITS as usize
            / 8
            + 1
            + SHA256_OUT_SIZE as usize
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            ..U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize];
        let res = pub_key.verify(
            &input_data_being_signed[0],
            input_one_sig_in_serialised_transaction,
        );
        assert!(res.is_ok());
        let input_two_sig_in_serialised_transaction = &signed_transaction_data[u32::BITS as usize
            / 8
            + 1
            + SHA256_OUT_SIZE as usize
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            + ECDSA_SIG_SIZE as usize
            + 1
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            + U32_SIZE
            + SHA256_OUT_SIZE as usize
            ..U32_SIZE
                + 1
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize
                + 1
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + U32_SIZE
                + SHA256_OUT_SIZE as usize
                + ECDSA_SIG_SIZE as usize];
        let res = pub_key.verify(
            &input_data_being_signed[1],
            input_two_sig_in_serialised_transaction,
        );
        assert!(res.is_ok());
    }
}
