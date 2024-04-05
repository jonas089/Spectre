// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use eth_types::Spec;
use itertools::Itertools;
use lightclient_circuits::witness::{
    beacon_header_multiproof_and_helper_indices, CommitteeUpdateArgs,
};
use log::debug;

use crate::get_light_client_update_at_period;
use eth2::{types::BlockId, BeaconNodeHttpClient};
use ethereum_types::LightClientUpdate;
use tree_hash::TreeHash;

/// Fetches LightClientUpdate from the beacon client and converts it to a [`CommitteeUpdateArgs`] witness
pub async fn fetch_rotation_args<S: Spec>(
    client: &BeaconNodeHttpClient,
) -> eyre::Result<CommitteeUpdateArgs<S>> {
    let block = client
        .get_beacon_headers_block_id(BlockId::Finalized)
        .await
        .map_err(|e| eyre::eyre!("Failed to get block id: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get block id: None"))?
        .data
        .header
        .message;

    let slot = block.slot.as_u64();
    let period = slot / (32 * 256);
    println!(
        "Fetching light client update at current Slot: {} at Period: {}",
        slot, period
    );

    let update = get_light_client_update_at_period::<S>(client, period).await?;
    rotation_args_from_update(&update).await
}

/// Converts a [`LightClientUpdateCapella`] to a [`CommitteeUpdateArgs`] witness.
pub async fn rotation_args_from_update<S: Spec>(
    update: &LightClientUpdate<S::EthSpec>,
) -> eyre::Result<CommitteeUpdateArgs<S>> {
    let update = update.clone();
    let next_sync_committee = update.next_sync_committee().clone();

    let pubkeys_compressed = next_sync_committee
        .pubkeys
        .iter()
        .map(|pk| pk.serialize().to_vec())
        .collect_vec();
    let mut sync_committee_branch = update.next_sync_committee_branch().as_ref().to_vec();

    sync_committee_branch.insert(0, next_sync_committee.aggregate_pubkey.tree_hash_root());
    let (attested_header_beacon, finalized_header_beacon) = match update {
        LightClientUpdate::Altair(_) => unimplemented!(),
        LightClientUpdate::Capella(update) => (
            update.attested_header.beacon,
            update.finalized_header.beacon,
        ),

        LightClientUpdate::Deneb(update) => (
            update.attested_header.beacon,
            update.finalized_header.beacon,
        ),
    };

    assert!(
        merkle_proof::verify_merkle_proof(
            next_sync_committee.pubkeys.tree_hash_root(),
            &sync_committee_branch,
            S::SYNC_COMMITTEE_PUBKEYS_DEPTH,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
            attested_header_beacon.state_root,
        ),
        "Execution payload merkle proof verification failed"
    );

    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &finalized_header_beacon,
            &[S::HEADER_STATE_ROOT_INDEX],
        );

    let args = CommitteeUpdateArgs::<S> {
        pubkeys_compressed,
        finalized_header: finalized_header_beacon,
        sync_committee_branch: sync_committee_branch
            .into_iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        _spec: PhantomData,
        finalized_header_multiproof,
        finalized_header_helper_indices,
    };
    Ok(args)
}

#[cfg(test)]
mod tests {
    use crate::get_light_client_bootstrap;
    use std::time::Duration;

    use super::*;
    use eth2::{SensitiveUrl, Timeouts};
    use eth_types::Testnet;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::halo2curves::bn256::Fr;
    use lightclient_circuits::{
        committee_update_circuit::CommitteeUpdateCircuit, util::AppCircuit,
    };
    use snark_verifier_sdk::CircuitExt;

    #[tokio::test]
    async fn test_rotation_circuit_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_testnet.json";
        const K: u32 = 20;
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );
        let witness = fetch_rotation_args::<Testnet>(&client).await.unwrap();
        let pinning = Eth2ConfigPinning::from_path(CONFIG_PATH);
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &witness,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();
    }

    #[tokio::test]
    async fn test_rotation_step_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_18.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_20.pkey",
            CONFIG_PATH,
            &CommitteeUpdateArgs::<Testnet>::default(),
            None,
        );
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );
        let mut witness = fetch_rotation_args::<Testnet, _>(&client).await.unwrap();
        let mut finalized_sync_committee_branch = {
            let block_root = client
                .get_beacon_block_root(BlockId::Slot(witness.finalized_header.slot))
                .await
                .unwrap();

            get_light_client_bootstrap::<Testnet, _>(&client, block_root)
                .await
                .unwrap()
                .current_sync_committee_branch
                .iter()
                .map(|n| n.to_vec())
                .collect_vec()
        };

        // Magic swap of sync committee branch
        finalized_sync_committee_branch.insert(0, witness.sync_committee_branch[0].clone());
        finalized_sync_committee_branch[1] = witness.sync_committee_branch[1].clone();
        witness.sync_committee_branch = finalized_sync_committee_branch;

        CommitteeUpdateCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            CONFIG_PATH,
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
