// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use eth2::types::StateId;
use eth2::BeaconNodeHttpClient;
use eth_types::Spec;
use ethereum_consensus_types::bls::BlsPublicKey;
// use ethereum_consensus_types::signing::{compute_domain, DomainType};
// use ethereum_consensus_types::{ LightClientBootstrap, LightClientFinalityUpdate};
use blst::min_pk as bls;
use ethereum_types::Domain;
use ethereum_types::ForkData;
use ethereum_types::{EthSpec, FixedVector, LightClientFinalityUpdate, PublicKey, PublicKeyBytes};
use itertools::Itertools;
use lightclient_circuits::witness::{beacon_header_multiproof_and_helper_indices, SyncStepArgs};
use ssz_rs::Vector;
use ssz_rs::{Merkleized, Node};
/// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_step_args<S: Spec, T: EthSpec>(
    client: &BeaconNodeHttpClient,
) -> eyre::Result<SyncStepArgs<S>>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
{
    let finality_update = client
        .get_beacon_light_client_finality_update()
        .await
        .map_err(|e| eyre::eyre!("Failed to get finality update: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get finality update: None"))?
        .data;

    let block_root = finality_update.finalized_header.beacon.canonical_root();

    let bootstrap = client
        .get_light_client_bootstrap::<T>(block_root)
        .await
        .map_err(|e| eyre::eyre!("Failed to get bootstrap: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get bootstrap: None"))?
        .data;

    let pubkeys_compressed = bootstrap.current_sync_committee.pubkeys;

    let attested_state_id = finality_update.attested_header.beacon.state_root;

    // let fork_version = client
    //     .get_fork(StateId::Root(attested_state_id))
    //     .await?
    //     .current_version;
    // let genesis_validators_root = client.get_genesis_details().await?.genesis_validators_root;
    // let fork_data = ForkData {
    //     genesis_validators_root,
    //     fork_version,
    // };

    let fork_version = client
        .get_beacon_states_fork(StateId::Root(attested_state_id))
        .await
        .unwrap()
        .unwrap()
        .data
        .current_version;

    let genesis_validators_root = client
        .get_beacon_genesis()
        .await
        .unwrap()
        .data
        .genesis_validators_root;

    // let fork_data = ForkData {
    //     genesis_validators_root,
    //     current_version,
    // };

    let domain = T::default_spec().compute_domain(
        Domain::SyncCommittee,
        fork_version,
        genesis_validators_root,
    );

    step_args_from_finality_update(finality_update, pubkeys_compressed, domain.into()).await
}

/// Converts a [`LightClientFinalityUpdate`] to a [`SyncStepArgs`] witness.
pub async fn step_args_from_finality_update<S: Spec, T: EthSpec>(
    finality_update: LightClientFinalityUpdate<T>,
    pubkeys_compressed: FixedVector<PublicKeyBytes, T::SyncCommitteeSize>,
    domain: [u8; 32],
) -> eyre::Result<SyncStepArgs<S>> {
    let pubkeys_uncompressed = pubkeys_compressed
        .iter()
        .map(|pk| {
            bls::PublicKey::uncompress(&pk.serialize())
                .unwrap()
                .serialize()
                .to_vec()
        })
        .collect_vec();

    let execution_payload_root = finality_update
        .finalized_header
        .execution
        .clone()
        .hash_tree_root()?
        .to_vec();
    let execution_payload_branch = finality_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|n| n.0.to_vec())
        .collect_vec();

    assert!(
        ssz_rs::is_valid_merkle_branch(
            Node::try_from(execution_payload_root.as_slice())?,
            &execution_payload_branch,
            S::EXECUTION_STATE_ROOT_DEPTH,
            S::EXECUTION_STATE_ROOT_INDEX,
            finality_update.finalized_header.beacon.body_root,
        )
        .is_ok(),
        "Execution payload merkle proof verification failed"
    );
    assert!(
        ssz_rs::is_valid_merkle_branch(
            finality_update
                .finalized_header
                .beacon
                .clone()
                .hash_tree_root()
                .unwrap(),
            &finality_update
                .finality_branch
                .iter()
                .map(|n| n.as_ref())
                .collect_vec(),
            S::FINALIZED_HEADER_DEPTH,
            S::FINALIZED_HEADER_INDEX,
            finality_update.attested_header.beacon.state_root,
        )
        .is_ok(),
        "Finality merkle proof verification failed"
    );

    // Proof length is 3
    let (attested_header_multiproof, attested_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut finality_update.attested_header.beacon.clone(),
            &[S::HEADER_SLOT_INDEX, S::HEADER_STATE_ROOT_INDEX],
        );
    // Proof length is 4
    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut finality_update.finalized_header.beacon.clone(),
            &[S::HEADER_SLOT_INDEX, S::HEADER_BODY_ROOT_INDEX],
        );

    Ok(SyncStepArgs {
        signature_compressed: finality_update
            .sync_aggregate
            .sync_committee_signature
            .to_bytes()
            .to_vec(),
        pubkeys_uncompressed,
        pariticipation_bits: finality_update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .by_vals()
            .collect_vec(),
        attested_header: finality_update.attested_header.beacon,
        finalized_header: finality_update.finalized_header.beacon,
        finality_branch: finality_update
            .finality_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        execution_payload_root: finality_update
            .finalized_header
            .execution
            .clone()
            .hash_tree_root()
            .unwrap()
            .to_vec(),
        execution_payload_branch: finality_update
            .finalized_header
            .execution_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        domain,
        _spec: PhantomData,
        attested_header_multiproof,
        attested_header_helper_indices,
        finalized_header_multiproof,
        finalized_header_helper_indices,
    })
}

#[cfg(test)]
mod tests {
    use eth_types::Testnet;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::halo2curves::bn256::Fr;
    use lightclient_circuits::{sync_step_circuit::StepCircuit, util::AppCircuit};

    use super::*;
    use beacon_api_client::mainnet::Client as MainnetClient;
    use reqwest::Url;

    #[tokio::test]
    async fn test_sync_step_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/sync_step_20.json";
        const K: u32 = 20;
        let params = gen_srs(K);

        let pk = StepCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_20.pkey",
            CONFIG_PATH,
            &SyncStepArgs::<Testnet>::default(),
            None,
        );
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let witness = fetch_step_args::<Testnet, _>(&client).await.unwrap();

        StepCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            CONFIG_PATH,
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
