use puffersecuresigner::eth2::eth_signing::BLSSignMsg;
use puffersecuresigner::{eth2::eth_types::*, strip_0x_prefix};

use serde::{Deserialize, Serialize};
use snap::raw::Decoder;
use ssz::Decode;
use tree_hash::TreeHash;

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub const BASE_DIR: &str = "./tests/consensus-spec-tests/tests/mainnet/capella/ssz_static/";

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct ExpectedRoot {
    root: String,
}

impl ExpectedRoot {
    fn from_file(p: &Path) -> Result<Root> {
        let root = yaml_decode_file::<ExpectedRoot>(p)?;
        let root: String = strip_0x_prefix!(root.root);
        let root_bytes = hex::decode(root)?;
        let mut root_out = Root::default();
        root_out.copy_from_slice(&root_bytes);
        Ok(root_out)
    }
}

pub fn yaml_decode<T: serde::de::DeserializeOwned>(string: &str) -> Result<T> {
    serde_yaml::from_str(string).with_context(|| format!("Yaml decode failed"))
}

pub fn yaml_decode_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let s =
        fs::read_to_string(path).with_context(|| format!("Unable to load {}", path.display()))?;
    yaml_decode(&s)
}

pub fn snappy_decode_file_to_eth_type<T: Decode + TreeHash>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("Unable to load {}", path.display()))?;
    let mut decoder = Decoder::new();
    let bytes = decoder
        .decompress_vec(&bytes)
        .with_context(|| format!("Error decoding snappy encoding for {}", path.display(),))?;
    match T::from_ssz_bytes(&bytes) {
        Ok(res) => Ok(res),
        Err(e) => bail!("Failed to decode to ssz type: {:?}", e),
    }
}

/// https://media.githubusercontent.com/media/ethereum/consensus-spec-tests/master/configs/mainnet.yaml
fn get_fork_info() -> ForkInfo {
    ForkInfo {
        fork: Fork {
            previous_version: [2, 0, 0, 0],
            current_version: [3, 0, 0, 0],
            epoch: 194048,
        },
        // From our validator on goerli
        genesis_validators_root: [
            4, 61, 176, 217, 168, 56, 19, 85, 30, 226, 243, 52, 80, 210, 55, 151, 117, 125, 67, 9,
            17, 169, 50, 5, 48, 173, 138, 14, 171, 196, 62, 251,
        ],
    }
}

fn get_testvec_file_names(start_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut file_pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
    let search_path = start_dir.join("ssz_random");

    for entry in fs::read_dir(search_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir()
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("case_")
        {
            let ssz_path = path.join("serialized.ssz_snappy");
            let root_path = path.join("roots.yaml");

            file_pairs.push((ssz_path, root_path));
        }
    }

    Ok(file_pairs)
}

fn get_test_vec_container<T: Decode + TreeHash>(ssz_file: &Path, root_file: &Path) -> Result<T> {
    let eth2_container = snappy_decode_file_to_eth_type::<T>(ssz_file)?;
    let root = ExpectedRoot::from_file(root_file)?;

    // Compare the derived tree_root_hash with expected
    if eth2_container.tree_hash_root().as_bytes() != root {
        bail!(
            "SSZ static container tree_root_hash =/= root, file: {:?}",
            ssz_file
        )
    }

    Ok(eth2_container)
}

fn get_test_vec_block(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let block = get_test_vec_container::<BeaconBlock>(ssz_file, root_file)?;

    let req = BlockRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        block,
    };
    let b = BLSSignMsg::BLOCK(req);
    Ok(b)
}

fn get_test_vec_block_v2(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let block_header = get_test_vec_container::<BeaconBlockHeader>(ssz_file, root_file)?;

    let req_wrapper = BlockV2RequestWrapper {
        version: "Capella".to_string(),
        block_header,
    };

    let req = BlockV2Request {
        fork_info: get_fork_info(),
        signingRoot: None,
        beacon_block: req_wrapper,
    };
    let b = BLSSignMsg::BLOCK_V2(req);
    Ok(b)
}

fn get_test_vec_attestation(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let attestation = get_test_vec_container::<Attestation>(ssz_file, root_file)?;

    let req = AttestationRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        attestation: attestation.data,
    };
    let a = BLSSignMsg::ATTESTATION(req);
    Ok(a)
}

fn get_test_vec_aggregate_and_proof(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let aggregate_and_proof = get_test_vec_container::<AggregateAndProof>(ssz_file, root_file)?;

    let req = AggregateAndProofRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        aggregate_and_proof,
    };
    let a = BLSSignMsg::AGGREGATE_AND_PROOF(req);
    Ok(a)
}

fn get_test_vec_deposit(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let deposit = get_test_vec_container::<DepositMessage>(ssz_file, root_file)?;

    let req = DepositRequest {
        signingRoot: None,
        deposit,
        genesis_fork_version: [0, 0, 0, 0],
    };
    let d = BLSSignMsg::DEPOSIT(req);
    Ok(d)
}

fn get_test_vec_voluntary_exit(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let voluntary_exit = get_test_vec_container::<VoluntaryExit>(ssz_file, root_file)?;

    let fork_info = get_fork_info();
    let req = VoluntaryExitRequest {
        fork_info,
        signingRoot: None,
        voluntary_exit,
    };
    let v = BLSSignMsg::VOLUNTARY_EXIT(req);
    Ok(v)
}

fn get_test_vec_sync_committee_message(ssz_file: &Path, root_file: &Path) -> Result<BLSSignMsg> {
    let sync_committee_message =
        get_test_vec_container::<SyncCommitteeMessage>(ssz_file, root_file)?;

    let req_wrapper = SyncCommitteeMessageRequestWrapper {
        slot: sync_committee_message.slot,
        beacon_block_root: sync_committee_message.beacon_block_root,
    };

    let req = SyncCommitteeMessageRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        sync_committee_message: req_wrapper,
    };
    let s = BLSSignMsg::SYNC_COMMITTEE_MESSAGE(req);
    Ok(s)
}

fn get_test_vec_sync_committee_selection_proof(
    ssz_file: &Path,
    root_file: &Path,
) -> Result<BLSSignMsg> {
    let sync_aggregator_selection_data =
        get_test_vec_container::<SyncAggregatorSelectionData>(ssz_file, root_file)?;

    let req = SyncCommitteeSelectionProofRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        sync_aggregator_selection_data,
    };
    let s = BLSSignMsg::SYNC_COMMITTEE_SELECTION_PROOF(req);
    Ok(s)
}

fn get_test_vec_sync_committee_contribution_and_proof(
    ssz_file: &Path,
    root_file: &Path,
) -> Result<BLSSignMsg> {
    let contribution_and_proof =
        get_test_vec_container::<ContributionAndProof>(ssz_file, root_file)?;

    let req = SyncCommitteeContributionAndProofRequest {
        fork_info: get_fork_info(),
        signingRoot: None,
        contribution_and_proof,
    };
    let s = BLSSignMsg::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(req);
    Ok(s)
}

pub fn get_all_test_vecs(container_name: &str) -> Result<Vec<BLSSignMsg>> {
    let path: PathBuf = [BASE_DIR, container_name].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();

    let func = match container_name {
        "Attestation" => get_test_vec_attestation,
        "BeaconBlock" => get_test_vec_block,
        "BeaconBlockHeader" => get_test_vec_block_v2,
        "AggregateAndProof" => get_test_vec_aggregate_and_proof,
        "DepositMessage" => get_test_vec_deposit,
        "VoluntaryExit" => get_test_vec_voluntary_exit,
        "SyncCommitteeMessage" => get_test_vec_sync_committee_message,
        "SyncAggregatorSelectionData" => get_test_vec_sync_committee_selection_proof,
        "ContributionAndProof" => get_test_vec_sync_committee_contribution_and_proof,
        _ => bail!("{container_name} is not a valid container"),
    };

    let mut test_vecs = Vec::new();

    for (ssz_file_path, root_file_path) in file_paths {
        let test_vec = func(ssz_file_path.as_path(), root_file_path.as_path()).unwrap();
        test_vecs.push(test_vec);
    }
    Ok(test_vecs)
}

#[test]
fn test_eth1_data() {
    let path: PathBuf = [BASE_DIR, "Eth1Data"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        get_test_vec_container::<Eth1Data>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_proposer_slashing() {
    let path: PathBuf = [BASE_DIR, "ProposerSlashing"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<ProposerSlashing>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_attester_slashing() {
    let path: PathBuf = [BASE_DIR, "AttesterSlashing"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<AttesterSlashing>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_deposit() {
    let path: PathBuf = [BASE_DIR, "Deposit"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<Deposit>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_voluntary_exit() {
    let path: PathBuf = [BASE_DIR, "VoluntaryExit"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<VoluntaryExit>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_sync_aggregate() {
    let path: PathBuf = [BASE_DIR, "SyncAggregate"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<SyncAggregate>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_bls_to_execution_changes() {
    let path: PathBuf = [BASE_DIR, "BLSToExecutionChange"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<BLSToExecutionChange>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_attestation() {
    let path: PathBuf = [BASE_DIR, "Attestation"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<Attestation>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_execution_payload() {
    let path: PathBuf = [BASE_DIR, "ExecutionPayload"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        get_test_vec_container::<ExecutionPayload>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_beacon_block_body() {
    let path: PathBuf = [BASE_DIR, "BeaconBlockBody"].iter().collect();
    let file_paths = get_testvec_file_names(&path).unwrap();
    for (ssz_file, root_file) in file_paths.iter() {
        dbg!(ssz_file);
        get_test_vec_container::<BeaconBlockBody>(ssz_file, root_file).unwrap();
    }
}

#[test]
fn test_block_ssz_static() {
    let path: PathBuf = [BASE_DIR, "BeaconBlock"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("BeaconBlock").unwrap();
}

#[test]
fn test_block_v2_ssz_static() {
    let path: PathBuf = [BASE_DIR, "BeaconBlockHeader"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("BeaconBlockHeader").unwrap();
}

#[test]
fn test_attestation_ssz_static() {
    let path: PathBuf = [BASE_DIR, "Attestation"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("Attestation").unwrap();
}

#[test]
fn test_aggregate_and_proof_ssz_static() {
    let path: PathBuf = [BASE_DIR, "AggregateAndProof"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("AggregateAndProof").unwrap();
}

#[test]
fn test_deposit_message_ssz_static() {
    let path: PathBuf = [BASE_DIR, "DepositMessage"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("DepositMessage").unwrap();
}

#[test]
fn test_voluntary_exit_ssz_static() {
    let path: PathBuf = [BASE_DIR, "VoluntaryExit"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("VoluntaryExit").unwrap();
}

#[test]
fn test_sync_committee_message_ssz_static() {
    let path: PathBuf = [BASE_DIR, "SyncCommitteeMessage"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("SyncCommitteeMessage").unwrap();
}

#[test]
fn test_sync_committee_selection_proof_ssz_static() {
    let path: PathBuf = [BASE_DIR, "SyncAggregatorSelectionData"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("SyncAggregatorSelectionData").unwrap();
}

#[test]
fn test_sync_committee_contribution_and_proof_ssz_static() {
    let path: PathBuf = [BASE_DIR, "ContributionAndProof"].iter().collect();
    dbg!(&path);
    get_all_test_vecs("ContributionAndProof").unwrap();
}
