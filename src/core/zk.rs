/// Errors happening during [`TypedAssignments::zero_balanced`] procedure. All
/// of them indicate either invalid/crafted input arguments, or failures in the
/// source of randomness.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum MalformedInput {
    /// both our and their allocations are empty; at least one value must be
    /// provided in any of them.
    NoOutput,

    /// random number generator produced non-random blinding factor {0} which is
    /// an inverse of the sum of the previously produced keys.
    RandomInverseKeys,

    /// one of inputs has an invalid blinding factor {0} exceeding field prime
    /// order.
    InvalidInputBlinding(BlindingFactor),

    /// invalid input blinding factors, which sum up to the inversion of their
    /// own selves.
    MalformedInputBlindings,

    /// blinding factors provided as an input are invalid; specifically they sum
    /// above the prime field order. This means the attempt to spend an invalid
    /// contract state; check that your program use validated data only.
    InputBlindingsInvalid,

    /// sum of randomly generated blinding factors perfectly equals the sum of
    /// input blinding factors. This indicates that the random generator is
    /// failed or hacked.
    RandomnessFailure,
}

impl TypedAssignments {
    pub fn zero_balanced(
        inputs: Vec<value::Revealed>,
        allocations_ours: BTreeMap<seal::Revealed, AtomicValue>,
        allocations_theirs: BTreeMap<SealEndpoint, AtomicValue>,
    ) -> Result<Self, MalformedInput> {
        use secp256k1_zkp::{Scalar, SecretKey};

        if allocations_ours.len() + allocations_theirs.len() == 0 {
            return Err(MalformedInput::NoOutput);
        }

        // Generate random blinding factors
        let mut rng = secp256k1_zkp::rand::thread_rng();
        // We will compute the last blinding factors from all others so they
        // sum up to 0, so we need to generate only n - 1 random factors
        let count = allocations_theirs.len() + allocations_ours.len();
        let mut blinding_factors = Vec::<_>::with_capacity(count);
        let mut blinding_output_sum = Scalar::ZERO;
        for _ in 0..(count - 1) {
            let bf = SecretKey::new(&mut rng);
            blinding_output_sum = bf
                .add_tweak(&blinding_output_sum)
                .map_err(|_| MalformedInput::RandomInverseKeys)?
                .into();
            blinding_factors.push(bf);
        }
        let blinding_input_sum = inputs.iter().try_fold(Scalar::ZERO, |acc, val| {
            let sk = SecretKey::from_slice(val.blinding.as_ref())
                .map_err(|_| MalformedInput::InvalidInputBlinding(val.blinding))?;
            sk.add_tweak(&acc)
                .map_err(|_| MalformedInput::MalformedInputBlindings)
                .map(Scalar::from)
        })?;

        if inputs.is_empty() {
            // if we have no inputs, we assign a random last blinding factor
            blinding_factors.push(SecretKey::new(&mut rng));
        } else {
            // the last blinding factor must be a correction value
            let input_sum = SecretKey::from_slice(&blinding_input_sum.to_be_bytes())
                .map_err(|_| MalformedInput::InputBlindingsInvalid)?;
            let mut blinding_correction = input_sum.negate();
            blinding_correction = blinding_correction
                .add_tweak(&blinding_output_sum)
                .map_err(|_| MalformedInput::RandomnessFailure)?;
            // We need the last factor to be equal to the difference
            blinding_factors.push(blinding_correction.negate());
        }

        let mut blinding_iter = blinding_factors.into_iter();
        let mut set: Vec<Assignment<_>> = allocations_ours
            .into_iter()
            .zip(blinding_iter.by_ref())
            .map(|((seal, amount), blinding)| {
                Assignment::revealed(seal, value::Revealed::with(amount, blinding))
            })
            .collect();
        set.extend(allocations_theirs.into_iter().zip(blinding_iter).map(
            |((seal_proto, amount), blinding)| {
                let state = value::Revealed::with(amount, blinding);
                match seal_proto {
                    SealEndpoint::ConcealedUtxo(seal) => {
                        Assignment::ConfidentialSeal { seal, state }
                    }
                    SealEndpoint::WitnessVout {
                        method,
                        vout,
                        blinding,
                    } => Assignment::Revealed {
                        // TODO: Add convenience constructor to `seal::Revealed`
                        seal: seal::Revealed {
                            method,
                            txid: None,
                            vout,
                            blinding,
                        },
                        state,
                    },
                }
            },
        ));

        Ok(Self::Value(set))
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    pub fn verify_commit_sum<C: Into<secp256k1_zkp::PedersenCommitment>>(
        positive: impl IntoIterator<Item = C>,
        negative: impl IntoIterator<Item = C>,
    ) -> bool {
        let positive = positive.into_iter().map(C::into).collect::<Vec<_>>();
        let negative = negative.into_iter().map(C::into).collect::<Vec<_>>();
        secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &positive, &negative)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use bitcoin::blockdata::transaction::Outpoint;
    use bitcoin_hashes::hex::{FromHex, ToHex};
    use bitcoin_hashes::{sha256, Hash};
    use bp::seals::txout::TxoSeal;
    use commit_verify::merkle::MerkleNode;
    use commit_verify::{merklize, CommitConceal, CommitEncode, ToMerkleSource};
    use secp256k1_zkp::rand::{thread_rng, Rng, RngCore};
    use secp256k1_zkp::{PedersenCommitment, SecretKey};
    use strict_encoding_test::test_vec_decoding_roundtrip;

    use super::super::{NodeId, OwnedRights, ParentOwnedRights};
    use super::*;
    use crate::contract::seal::Revealed;
    use crate::schema;

    // Real data used for creation of above variants
    // Used in tests to ensure operations of AssignmentVariants gives
    // deterministic results

    // Txids to generate seals
    static TXID_VEC: [&str; 4] = [
        "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06",
        "12072893d951c633dcafb4d3074d1fc41c5e6e64b8d53e3b0705c41bc6679d54",
        "8f75db9f89c7c75f0a54322f18cd4d557ae75c24a8e5a95eae13fe26edc2d789",
    ];

    // State data used in CustomData type Assignments
    static STATE_DATA: [&str; 4] = [
        "e70a36e2ce51d31d4cf5d6731fa63738648127db833715d39652d86d927d4888",
        "408e331ebce96ca98cfb7b8a6286a79300379eed6395636e6d103017d474039f",
        "c6411aea082e2c5d74347368677db69545126237d5ed78faa0846352f5383f95",
        "277fb00655e2523424677686c24d90fba6b70869050ae204782e8ef0ab8049c6",
    ];

    // Confidential seals for Declarative Assignments
    static DECLARATIVE_OUTPOINT_HASH: [&str; 4] = [
        "58f3ea4817a12aa6f1007d5b3d24dd2940ce40f8498029e05f1dc6465b3d65b4",
        "6b3c1bee0bd431f53e6c099890fdaf51b8556a6dcd61c6150ca055d0e1d4a524",
        "9a17566abc006cf335fd96d8f8a4136526d85493a85ebe875abbbee19795c496",
        "c843ac6b197ae371191264cc0e4ed18a910b5522a0bad72a24f2080c170e2053",
    ];

    // Confidential seals for Pedersan type Assignments
    static PEDERSAN_OUTPOINT_HASH: [&str; 4] = [
        "281543d7f791d4b4f8ef1196e436bc3286a5505f7bafd978d4af9be6f112e1b4",
        "32d71a47d8ff6015fc58525985af7346e0802c7ad065ad79335602c7a6562ab3",
        "68955a27e1ffde810fcfdd18697eb59aa4f7b0afde2a8193cd28184b729b5195",
        "698c43d973bec68540e6df67137785e40be6d29def4888ada3cd7b7884b37f62",
    ];

    // Confidential seals for CustomData type Assignments
    static HASH_OUTPOINT_HASH: [&str; 4] = [
        "7efe71b7a37a39da798774ca6b09def9724d81303892d55cac3edb0dc8340a3a",
        "9565d29461c863e013c26d176a9929307286963322849a1dc6c978e5c70c8d52",
        "9b64a3024632f0517d8a608cb29902f7083eab0ac25d2827a5ef27e9a68b18f9",
        "dc0d0d7139a3ad6010a210e5900201979a1a09047b10a877688ee5a740ae215a",
    ];

    // Generic encode-decode testing
    #[test]
    #[ignore]
    fn test_encoded_data() {
        let _: TypedAssignments = test_vec_decoding_roundtrip(HASH_VARIANT).unwrap();
        let _: TypedAssignments = test_vec_decoding_roundtrip(PEDERSAN_VARIANT).unwrap();
        let _: TypedAssignments = test_vec_decoding_roundtrip(DECLARATIVE_VARIANT).unwrap();
    }

    fn zero_balance(
        input_amounts: &[u64],
        output_amounts: &[u64],
        partition: usize,
    ) -> (Vec<PedersenCommitment>, Vec<PedersenCommitment>) {
        let mut rng = thread_rng();

        // Create revealed amount from input amounts
        let input_revealed: Vec<value::Revealed> = input_amounts[..]
            .into_iter()
            .map(|amount| value::Revealed::with_amount(*amount, &mut rng))
            .collect();

        // Allocate Txid vector of size of the output vector
        let mut txid_vec: Vec<bitcoin::Txid> = Vec::with_capacity(output_amounts.len());

        // Fill the txid vector with random txids.
        for _ in 0..output_amounts.len() {
            let mut bytes: [u8; 32] = [0; 32];
            rng.fill(&mut bytes[..]);
            let txid = bitcoin::Txid::from_hex(&bytes.to_vec().to_hex()[..]).unwrap();
            txid_vec.push(txid);
        }

        // Take first two amounts to create our allocations
        let zip_data = txid_vec[..partition]
            .iter()
            .zip(output_amounts[..partition].iter());

        // Create our allocations
        let ours: SealValueMap = zip_data
            .map(|(txid, amount)| {
                (
                    Revealed::from(Outpoint::new(*txid, rng.gen_range(0..=10))),
                    amount.clone(),
                )
            })
            .collect();

        // Take next two amounts for their allocations
        let zip_data2 = txid_vec[partition..]
            .iter()
            .zip(output_amounts[partition..].iter());

        // Create their allocations
        let theirs: EndpointValueMap = zip_data2
            .map(|(txid, amount)| {
                (
                    SealEndpoint::ConcealedUtxo(
                        Revealed::from(Outpoint::new(*txid, rng.gen_range(0..=10)))
                            .commit_conceal(),
                    ),
                    amount.clone(),
                )
            })
            .collect();

        // Balance both the allocations against input amounts
        let balanced =
            TypedAssignments::zero_balanced(input_revealed.clone(), ours, theirs).unwrap();

        // Extract balanced confidential output amounts
        let outputs: Vec<PedersenCommitment> = balanced
            .to_confidential_state_pedersen()
            .iter()
            .map(|confidential| confidential.commitment)
            .collect();

        // Create confidential input amounts
        let inputs: Vec<PedersenCommitment> = input_revealed
            .iter()
            .map(|revealed| revealed.commit_conceal().commitment)
            .collect();

        (inputs, outputs)
    }

    fn zero_balance_verify(
        input_amounts: &[u64],
        output_amounts: &[u64],
        partition: usize,
    ) -> bool {
        let (inputs, outputs) = zero_balance(input_amounts, output_amounts, partition);
        value::Confidential::verify_commit_sum(inputs, outputs)
    }

    #[test]
    fn test_zero_balance_nonoverflow() {
        assert!(zero_balance_verify(
            &[core::u64::MAX, 1],
            &[1, core::u64::MAX],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u64::MAX, core::u64::MAX],
            &[core::u64::MAX, core::u64::MAX],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u32::MAX as u64, core::u32::MAX as u64],
            &[core::u32::MAX as u64 + core::u32::MAX as u64],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u32::MAX as u64, core::u32::MAX as u64, core::u64::MAX],
            &[core::u64::MAX, (core::u32::MAX as u64) * 2],
            1
        ));
    }

    #[test]
    fn test_zero_balance_single() {
        // test equal inputs and outputs
        let single_amounts = vec![
            [0u64],
            [1u64],
            [core::u16::MAX as u64],
            [core::u32::MAX as u64],
            [core::u64::MAX - 1u64],
            [core::u64::MAX],
        ];

        for vec in single_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }
    }

    #[test]
    fn test_zero_balance_double() {
        let double_amounts = vec![[(core::u32::MAX - 1) as u64, (core::u32::MAX - 1) as u64], [
            core::u32::MAX as u64,
            core::u32::MAX as u64,
        ]];

        for vec in double_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }
    }

    #[test]
    fn test_zero_balance_multiple() {
        let multiple_amounts = vec![
            [0u64, 0u64, 0u64, 0u64],
            [0u64, 1u64, 0u64, 1u64],
            [1u64, 2u64, 3u64, core::u64::MAX],
            [10u64, 20u64, 30u64, 40u64],
            [0u64, 197642u64, core::u64::MAX, 476543u64],
            [core::u64::MAX, core::u64::MAX, core::u64::MAX, core::u64::MAX],
        ];

        for vec in multiple_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }

        // Test when ours is empty
        assert!(zero_balance_verify(
            &multiple_amounts[2],
            &multiple_amounts[2],
            0
        ));

        // Test when theirs is empty
        assert!(zero_balance_verify(
            &multiple_amounts[4],
            &multiple_amounts[4],
            multiple_amounts[4].len()
        ));
    }

    #[test]
    fn test_zero_balance_negative() {
        // Test when input.sum() != output.sum()
        // When they only differ by 1
        // When they differ by core::u64::MAX
        assert!(!zero_balance_verify(
            &[0u64, 1u64, 0u64, 1u64],
            &[1u64, 2u64, 3u64, core::u64::MAX],
            2
        ));
        assert!(!zero_balance_verify(
            &[1u64, 2u64, 3u64, core::u64::MAX],
            &[10u64, 20u64, 30u64, 40u64],
            2
        ));
        assert!(!zero_balance_verify(
            &[10u64, 20u64, 30u64, 40u64],
            &[0u64, 197642u64, core::u64::MAX, 476543u64],
            2
        ));
        assert!(!zero_balance_verify(
            &[0u64, 197642u64, core::u64::MAX, 476543u64],
            &[core::u64::MAX, core::u64::MAX, core::u64::MAX, core::u64::MAX],
            2
        ));
        assert!(!zero_balance_verify(&[1, 2, 3, 4], &[1, 2, 3, 5], 2));
        assert!(!zero_balance_verify(
            &[1, 2, 3, 0],
            &[1, 2, 3, core::u64::MAX],
            2
        ));
    }

    #[test]
    fn test_zero_balance_random() {
        let mut rng = thread_rng();

        // Test random inputs and outputs
        // Randomly distributed between ours and theirs allocation
        for _ in 0..5 {
            // Randomly generate number of amounts between 1 to 20
            let input_length = rng.gen_range(1..=20);

            // Randomly fill the amount vector
            let mut input_amounts = vec![0; input_length];
            for index in 0..input_length {
                // keep the amount value low for faster testing
                input_amounts[index] = rng.gen_range::<u64, _>(100_000..=100_000_000_000);
            }
            let input_sum: u64 = input_amounts.iter().sum();

            // Create an output amount vector such that
            // input.sum() = output.sum(), but
            // input.count() != output.count()

            let mut output_amounts = vec![0u64; rng.gen_range(1..=20)];
            let output_length = output_amounts.len();

            // Add random values to output amounts until the last element
            for index in 0..output_length - 1 {
                output_amounts[index] = rng.gen_range::<u64, _>(100_000..=100_000_000_000);
            }
            let output_sum: u64 = output_amounts.iter().sum();

            // Balance input and output amount vector based on their sums
            if input_sum == output_sum {
                continue;
            } else if output_sum > input_sum {
                input_amounts[input_length - 1] += output_sum - input_sum;
            } else {
                output_amounts[output_length - 1] += input_sum - output_sum;
            }

            let (inputs, outputs) = zero_balance(
                &input_amounts[..],
                &output_amounts[..],
                rng.gen_range(0..=output_length),
            );
            // Check if test passes
            assert!(value::Confidential::verify_commit_sum(&inputs, &outputs));

            // Check non-equivalent amounts do not verify
            if input_length > 1 {
                assert_eq!(
                    value::Confidential::verify_commit_sum(&inputs[..(input_length - 1)], &outputs),
                    false
                );
            } else if output_length > 1 {
                assert_eq!(
                    value::Confidential::verify_commit_sum(
                        &inputs,
                        &outputs[..(output_length - 1)]
                    ),
                    false
                );
            }
        }
    }
}
