// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    gadget::crypto::{HashInstructions, Sha256ChipWide, ShaBitGateManager, ShaCircuitBuilder},
    poseidon::{g1_array_poseidon, poseidon_committee_commitment_from_compressed},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    util::{bytes_be_to_u128, AppCircuit, CommonGateManager, Eth2ConfigPinning, IntoWitness},
    witness::{self, HashInput, HashInputChunk},
    Eth2CircuitBuilder,
};
use eth_types::{Field, Spec, LIMB_BITS, NUM_LIMBS};
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage, flex_gate::threads::CommonCircuitBuilder, GateInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{self, Bn256},
        plonk::Error,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    safe_types::SafeTypeChip,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{utils::decode_into_bn, ProperCrtUint},
    bls12_381::FpChip,
    fields::FieldChip,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use ssz_rs::Merkleized;
use std::{
    env::var,
    fs::File,
    io::{Read, Result as IoResult, Write},
    iter,
    marker::PhantomData,
    vec,
};

#[derive(Clone, Debug, Default)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    pub fn assign_virtual(
        builder: &mut ShaCircuitBuilder<F, ShaBitGateManager<F>>,
        fp_chip: &FpChip<F>,
        args: &witness::CommitteeUpdateArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let range = fp_chip.range();

        let sha256_chip = Sha256ChipWide::new(range);

        let compressed_encodings = args
            .pubkeys_compressed
            .iter()
            .map(|bytes| {
                assert_eq!(bytes.len(), 48);
                builder
                    .main()
                    .assign_witnesses(bytes.iter().map(|&b| F::from(b as u64)))
            })
            .collect_vec();

        // Note: This is the root of the public keys list in the SyncCommittee struct
        // not the root of the SyncCommittee struct itself.
        let committee_root_ssz =
            Self::sync_committee_root_ssz(builder, &sha256_chip, compressed_encodings.clone())?;

        let poseidon_commit = {
            let (pubkeys_x, y_signs_packed) =
                Self::decode_pubkeys_x(builder.main(), fp_chip, compressed_encodings);
            g1_array_poseidon(builder.main(), fp_chip, pubkeys_x, y_signs_packed)?
        };

        // Finalized header
        let finalized_state_root = args
            .finalized_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let finalized_header_root = ssz_merkleize_chunks(
            builder,
            &sha256_chip,
            [
                args.finalized_header.slot.into_witness(),
                args.finalized_header.proposer_index.into_witness(),
                args.finalized_header.parent_root.as_ref().into_witness(),
                finalized_state_root.clone().into(),
                args.finalized_header.body_root.as_ref().into_witness(),
            ],
        )?;

        // Verify that the sync committee root is in the finalized state root
        verify_merkle_proof(
            builder,
            &sha256_chip,
            args.sync_committee_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            committee_root_ssz.clone().into(),
            &finalized_state_root,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
        )?;

        let finalized_header_root_lo_hi = bytes_be_to_u128(
            builder.main(),
            &range.gate,
            SafeTypeChip::unsafe_to_fix_len_bytes_vec(finalized_header_root.clone(), 32).bytes(),
        );

        let public_inputs = iter::once(poseidon_commit)
            .chain(finalized_header_root_lo_hi.into_iter().rev()) // as hi/lo
            .collect();

        Ok(public_inputs)
    }

    /// Decodes the pub keys bytes into and X coordinate reperesented as a big integers.
    ///
    /// Assumes that input bytes are in Big-Endian encoding.
    fn decode_pubkeys_x(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'_, F>,
        compressed_encodings: impl IntoIterator<Item = Vec<AssignedValue<F>>>,
    ) -> (Vec<ProperCrtUint<F>>, Vec<AssignedValue<F>>) {
        let gate = fp_chip.gate();

        let (x_bigints, y_signs): (Vec<_>, Vec<_>) = compressed_encodings
            .into_iter()
            .map(|mut assigned_bytes| {
                // following logic is for little endian decoding but input bytes are in BE, therefore we reverse them.
                assigned_bytes.reverse();
                // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_COMPRESSED from specification
                assert_eq!(assigned_bytes.len(), 48);
                // masked byte from compressed representation
                let masked_byte = &assigned_bytes[47];
                // clear the flag bits from a last byte of compressed pubkey.
                // we are using [`clear_3_bits`] function which appears to be just as useful here as for public input commitment.
                let (cleared_byte, y_sign) = {
                    let bits = gate.num_to_bits(ctx, *masked_byte, 8);
                    let cleared = gate.bits_to_num(ctx, &bits[..5]);
                    (cleared, bits[5]) // 3 MSB bits are cleared, 3-rd of those is a sign bit
                };
                // Use the cleared byte to construct the x coordinate
                let assigned_x_bytes_cleared =
                    [&assigned_bytes.as_slice()[..48 - 1], &[cleared_byte]].concat();

                let x = decode_into_bn::<F>(
                    ctx,
                    gate,
                    assigned_x_bytes_cleared,
                    &fp_chip.limb_bases,
                    fp_chip.limb_bits(),
                );

                (x, y_sign)
            })
            .unzip();

        let signs_packed = y_signs
            .chunks(F::CAPACITY as usize - 1)
            .map(|chunk| gate.bits_to_num(ctx, chunk))
            .collect_vec();

        (x_bigints, signs_packed)
    }

    fn sync_committee_root_ssz<GateManager: CommonGateManager<F>>(
        builder: &mut ShaCircuitBuilder<F, GateManager>,
        hasher: &impl HashInstructions<F, CircuitBuilder = ShaCircuitBuilder<F, GateManager>>,
        compressed_encodings: impl IntoIterator<Item = Vec<AssignedValue<F>>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let pubkeys_hashes: Vec<HashInputChunk<QuantumCell<F>>> = compressed_encodings
            .into_iter()
            .map(|bytes| {
                let input: HashInputChunk<_> = bytes
                    .into_iter()
                    .pad_using(64, |_| builder.main().load_zero())
                    .into();
                hasher
                    .digest(builder, HashInput::Single(input))
                    .map(|r| r.into_iter().collect_vec().into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        ssz_merkleize_chunks(builder, hasher, pubkeys_hashes)
    }

    // Computes public inputs to `CommitteeUpdateCircuit` matching the in-circuit logic from `synthesise` method.
    // Note, this function outputes only instances of the `CommitteeUpdateCircuit` proof, not the aggregated proof which will also include 12 accumulator limbs.
    pub fn get_instances(
        args: &witness::CommitteeUpdateArgs<S>,
        limb_bits: usize,
    ) -> Vec<Vec<bn256::Fr>>
    where
        [(); S::SYNC_COMMITTEE_SIZE]:,
    {
        let poseidon_commitment =
            poseidon_committee_commitment_from_compressed(&args.pubkeys_compressed, limb_bits);

        let finalized_header_root = args.finalized_header.clone().hash_tree_root().unwrap();

        let finalized_header_root_hilo = {
            let bytes = finalized_header_root.as_ref();
            let hash_lo = u128::from_be_bytes(bytes[16..].try_into().unwrap());
            let hash_hi = u128::from_be_bytes(bytes[..16].try_into().unwrap());
            [hash_lo, hash_hi].map(bn256::Fr::from_u128)
        };

        let instance_vec = iter::once(poseidon_commitment)
            .chain(finalized_header_root_hilo)
            .collect();

        vec![instance_vec]
    }
}

impl<S: Spec> AppCircuit for CommitteeUpdateCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::CommitteeUpdateArgs<S>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        witness: &witness::CommitteeUpdateArgs<S>,
        params: &ParamsKZG<Bn256>,
    ) -> Result<impl crate::util::PinnableCircuit<bn256::Fr>, Error> {
        let k = params.k() as usize;
        let lookup_bits = pinning
            .as_ref()
            .map_or(k - 1, |p| p.params.lookup_bits.unwrap_or(k - 1));
        let mut builder = Eth2CircuitBuilder::<ShaBitGateManager<bn256::Fr>>::from_stage(stage)
            .use_k(k)
            .use_instance_columns(1);
        let range = builder.range_chip(lookup_bits);
        let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);

        let assigned_instances = Self::assign_virtual(&mut builder, &fp_chip, witness)?;
        builder.set_instances(0, assigned_instances);

        match stage {
            CircuitBuilderStage::Prover => {
                if let Some(pinning) = pinning {
                    builder.set_params(pinning.params);
                    builder.set_break_points(pinning.break_points);
                }
            }
            _ => {
                builder.calculate_params(Some(
                    var("MINIMUM_ROWS")
                        .unwrap_or_else(|_| "0".to_string())
                        .parse()
                        .unwrap(),
                ));
            }
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    fn write_struct_to_file<T: Serialize>(data: &T, file_path: &str) -> IoResult<()> {
        let encoded: Vec<u8> = bincode::serialize(data).expect("Failed to serialize");
        let mut file = File::create(file_path)?;
        file.write_all(&encoded)?;
        Ok(())
    }

    fn read_struct_from_file<T: for<'de> Deserialize<'de>>(file_path: &str) -> IoResult<T> {
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Deserialization can use the buffer's data, no lifetime issue
        let decoded: T = bincode::deserialize(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(decoded)
    }
    use std::{fs, io::Cursor};

    use crate::{
        aggregation_circuit::AggregationConfigPinning, gadget::crypto::ShaFlexGateManager,
        util::Halo2ConfigPinning, witness::CommitteeUpdateArgs,
    };

    use super::*;
    use bn256::G1Affine;
    use eth_types::Testnet;
    use ff::Field;
    use halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        halo2_proofs::{
            halo2curves::bn256::Fr,
            plonk::{create_proof, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
            poly::{
                commitment::Params,
                kzg::{
                    commitment::{KZGCommitmentScheme, ParamsKZG},
                    multiopen::{ProverSHPLONK, VerifierSHPLONK},
                    strategy::SingleStrategy,
                },
                VerificationStrategy,
            },
            transcript::{
                Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
                TranscriptWriterBuffer,
            },
        },
        utils::fs::gen_srs,
    };
    use rand::rngs::OsRng;
    use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk};
    use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, CircuitExt, Snark};

    fn load_circuit_args() -> CommitteeUpdateArgs<Testnet> {
        serde_json::from_slice(&fs::read("../test_data/rotation_512.json").unwrap()).unwrap()
    }

    fn gen_application_snark(
        params: &ParamsKZG<bn256::Bn256>,
        pk: &ProvingKey<bn256::G1Affine>,
        witness: &CommitteeUpdateArgs<Testnet>,
        pinning_path: &str,
    ) -> Snark {
        CommitteeUpdateCircuit::<Testnet, Fr>::gen_snark_shplonk(
            params,
            pk,
            pinning_path,
            None::<String>,
            witness,
        )
        .unwrap()
    }

    #[test]
    fn test_prove_and_verify_plonk() {
        const K: u32 = 20;
        let mut file = File::open("./params/kzg_bn254_20.srs").expect("Failed to open params!");

        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)
            .expect("Failed to read params!");

        let params: ParamsKZG<Bn256> =
            ParamsKZG::read(&mut Cursor::new(&buffer)).expect("Failed to read buffer :(");

        const PINNING_PATH: &str = "./config/committee_update_20.json";
        const PKEY_PATH: &str = "../build/committee_update_20.pkey";

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::create_pk(
            &params,
            PKEY_PATH,
            PINNING_PATH,
            &CommitteeUpdateArgs::<Testnet>::default(),
            None,
        );

        println!("[Ok] Proving Key");

        let witness = load_circuit_args();

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Prover,
            Some(Eth2ConfigPinning::from_path(PINNING_PATH)),
            &witness,
            &params,
        )
        .expect("Failed to construct circuit");

        println!("[Ok] Construct Circuit");

        let reader: Vec<u8> = vec![];
        let mut transcript_writer: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> =
            Blake2bWrite::init(reader);
        println!("[Ok] Read Transcript");

        let vk: &VerifyingKey<G1Affine> = pk.get_vk();

        let circuit_params = circuit.params();
        //let vk_serialized = vk.to_bytes(halo2_base::halo2_proofs::SerdeFormat::RawBytes);

        let witness_serialized = bincode::serialize(&witness).unwrap();
        let witness_deserialized: CommitteeUpdateArgs<Testnet> =
            bincode::deserialize(&witness_serialized).unwrap();

        /*
        let instances = circuit.instances();
        let instances_ref: Vec<&[Fr]> = instances.iter().map(|inner| inner.as_slice()).collect();
        let instances_nested_ref: Vec<&[&[Fr]]> = instances_ref
            .iter()
            .map(|inner| std::slice::from_ref(inner))
            .collect();

        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<Bn256>,
            Challenge255<G1Affine>,
            OsRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(
            &params,
            &pk,
            &[circuit],
            &instances_nested_ref,
            OsRng,
            &mut transcript_writer,
        )
        .expect("Failed to generate proof!");

        let reader_final = transcript_writer.finalize();

        println!("[Ok] Proof");

        let mut transcript_reader = Blake2bRead::init(&reader_final[..]);

        write_struct_to_file(&reader_final, "proof.txt").expect("Failed to write proof");
        write_struct_to_file(&instances, "instances.txt").expect("Failed to write instances");
        write_struct_to_file(
            &vk.to_bytes(halo2_base::halo2_proofs::SerdeFormat::RawBytes),
            "vk.txt",
        )
        .expect("Failed to write vk");

        verify_proof::<
            _,
            VerifierSHPLONK<Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<_, G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<Bn256>,
        >(
            &params,
            &vk,
            SingleStrategy::new(&params),
            &instances_nested_ref,
            &mut transcript_reader,
        )
        .expect("Failed to verify!");

        println!("[Yippie]");
        */
    }

    #[test]
    fn test_committee_update_proofgen() {
        const K: u32 = 20;
        let params = gen_srs(K);

        const PINNING_PATH: &str = "./config/committee_update_20.json";
        const PKEY_PATH: &str = "../build/committee_update_20.pkey";

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::create_pk(
            &params,
            PKEY_PATH,
            PINNING_PATH,
            &CommitteeUpdateArgs::<Testnet>::default(),
            None,
        );

        let witness = load_circuit_args();

        let _ = CommitteeUpdateCircuit::<Testnet, Fr>::gen_proof_shplonk(
            &params,
            &pk,
            PINNING_PATH,
            &witness,
        )
        .expect("proof generation & verification should not fail");
    }

    #[test]
    fn test_committee_update_aggregation_evm() {
        const APP_K: u32 = 20;
        const APP_PK_PATH: &str = "../build/committee_update_20.pkey";
        const APP_PINNING_PATH: &str = "./config/committee_update_20.json";
        const AGG_K: u32 = 24;
        const AGG_PK_PATH: &str = "../build/committee_update_verifier_24.pkey";
        const AGG_CONFIG_PATH: &str = "./config/committee_update_verifier_24.json";
        let params_app = gen_srs(APP_K);

        let pk_app = CommitteeUpdateCircuit::<Testnet, Fr>::create_pk(
            &params_app,
            APP_PK_PATH,
            APP_PINNING_PATH,
            &CommitteeUpdateArgs::<Testnet>::default(),
            None,
        );

        let witness = load_circuit_args();
        let snark = vec![gen_application_snark(
            &params_app,
            &pk_app,
            &witness,
            APP_PINNING_PATH,
        )];

        let agg_params = gen_srs(AGG_K);
        println!("agg_params k: {:?}", agg_params.k());

        let pk =
            AggregationCircuit::create_pk(&agg_params, AGG_PK_PATH, AGG_CONFIG_PATH, &snark, None);

        let agg_config = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);

        let agg_circuit = AggregationCircuit::create_circuit(
            CircuitBuilderStage::Prover,
            Some(agg_config),
            &snark,
            &agg_params,
        )
        .unwrap();

        let instances = agg_circuit.instances();
        let num_instances = agg_circuit.num_instance();

        println!("num_instances: {:?}", num_instances);
        println!("instances: {:?}", instances);

        let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code =
            AggregationCircuit::gen_evm_verifier_shplonk(&agg_params, &pk, None::<String>, &snark)
                .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
