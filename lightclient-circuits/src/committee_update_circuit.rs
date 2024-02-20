// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    gadget::crypto::{HashInstructions, Sha256ChipWide, ShaBitGateManager, ShaCircuitBuilder},
    poseidon::{fq_array_poseidon, poseidon_hash_fq_array},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_multiproof, verify_merkle_proof},
    sync_step_circuit::clear_3_bits,
    util::{AppCircuit, CommonGateManager, Eth2ConfigPinning, IntoWitness},
    witness::{self, HashInput, HashInputChunk},
    Eth2CircuitBuilder,
};
use eth_types::{Field, Spec, LIMB_BITS, NUM_LIMBS};
use halo2_base::{
    gates::{circuit::CircuitBuilderStage, flex_gate::threads::CommonCircuitBuilder},
    halo2_proofs::{
        halo2curves::bn256::{self, Bn256},
        plonk::Error,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{utils::decode_into_bn, ProperCrtUint},
    bls12_381::FpChip,
    fields::FieldChip,
};
use halo2curves::bls12_381;
use itertools::Itertools;
use ssz_rs::{Merkleized, Vector};
use std::{env::var, iter, marker::PhantomData, vec};
use tree_hash::TreeHash;
/// `CommitteeUpdateCircuit` maps next sync committee SSZ root in the finalized state root to the corresponding Poseidon commitment to the public keys.
///
/// Assumes that public keys are BLS12-381 points on G1; `sync_committee_branch` is exactly `S::SYNC_COMMITTEE_PUBKEYS_DEPTH` hashes in lenght.
///
/// The circuit exposes two public inputs:
/// - `poseidon_commit` is a Poseidon "onion" commitment to the X coordinates of sync committee public keys. Coordinates are expressed as big-integer with two limbs of LIMB_BITS * 2 bits.
/// - `committee_root_ssz` is a Merkle SSZ root of the list of sync committee public keys.
/// - `finalized_header_root` is a Merkle SSZ root of the finalized header.
#[derive(Clone, Debug, Default)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    pub fn synthesize(
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
            let pubkeys_x = Self::decode_pubkeys_x(builder.main(), fp_chip, compressed_encodings);
            fq_array_poseidon(builder.main(), fp_chip, &pubkeys_x)?
        };

        // Finalized header
        let finalized_state_root = args
            .finalized_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let finalized_header_root = args
            .finalized_header
            .tree_hash_root()
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();

        verify_merkle_multiproof(
            builder,
            &sha256_chip,
            args.finalized_header_multiproof
                .iter()
                .map(|w| w.clone().into_witness()),
            [finalized_state_root.clone().into()],
            &finalized_header_root,
            [S::HEADER_STATE_ROOT_INDEX],
            args.finalized_header_helper_indices.clone(),
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

        let public_inputs = iter::once(poseidon_commit)
            .chain(committee_root_ssz)
            .chain(finalized_header_root)
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
    ) -> Vec<ProperCrtUint<F>> {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        compressed_encodings
            .into_iter()
            .map(|mut assigned_bytes| {
                // following logic is for little endian decoding but input bytes are in BE, therefore we reverse them.
                assigned_bytes.reverse();
                // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_COMPRESSED from specification
                assert_eq!(assigned_bytes.len(), 48);
                // masked byte from compressed representation
                let masked_byte = &assigned_bytes[48 - 1];
                // clear the flag bits from a last byte of compressed pubkey.
                // we are using [`clear_3_bits`] function which appears to be just as useful here as for public input commitment.
                let cleared_byte = clear_3_bits(ctx, range, masked_byte);
                // Use the cleared byte to construct the x coordinate
                let assigned_x_bytes_cleared =
                    [&assigned_bytes.as_slice()[..48 - 1], &[cleared_byte]].concat();

                decode_into_bn::<F>(
                    ctx,
                    gate,
                    assigned_x_bytes_cleared,
                    &fp_chip.limb_bases,
                    fp_chip.limb_bits(),
                )
            })
            .collect()
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
        let pubkeys_x = args.pubkeys_compressed.iter().cloned().map(|mut bytes| {
            bytes[0] &= 0b00011111;
            bls12_381::Fq::from_bytes_be(&bytes.try_into().unwrap())
                .expect("bad bls12_381::Fq encoding")
        });

        let poseidon_commitment = poseidon_hash_fq_array::<bn256::Fr>(pubkeys_x, limb_bits);

        let mut pk_vector: Vector<Vector<u8, 48>, { S::SYNC_COMMITTEE_SIZE }> = args
            .pubkeys_compressed
            .as_slice()
            .iter()
            .map(|v| v.as_slice().try_into().unwrap())
            .collect_vec()
            .try_into()
            .unwrap();

        let ssz_root = pk_vector.hash_tree_root().unwrap();

        let finalized_header_root = args.finalized_header.tree_hash_root();

        let instance_vec = iter::once(poseidon_commitment)
            .chain(ssz_root.as_ref().iter().map(|b| bn256::Fr::from(*b as u64)))
            .chain(
                finalized_header_root
                    .as_ref()
                    .iter()
                    .map(|b| bn256::Fr::from(*b as u64)),
            )
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

        let assigned_instances = Self::synthesize(&mut builder, &fp_chip, witness)?;
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
    use std::fs;

    use crate::{
        aggregation_circuit::AggregationConfigPinning, util::Halo2ConfigPinning,
        witness::CommitteeUpdateArgs,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Testnet;
    use halo2_base::{
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::ProvingKey,
            poly::{commitment::Params, kzg::commitment::ParamsKZG},
        },
        utils::fs::gen_srs,
    };
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
    fn test_committee_update_circuit() {
        const K: u32 = 20;
        let witness = load_circuit_args();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let instance = CommitteeUpdateCircuit::<Testnet, Fr>::get_instances(&witness, LIMB_BITS);

        let timer = start_timer!(|| "committee_update mock prover");
        let prover = MockProver::<Fr>::run(K, &circuit, instance).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
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
