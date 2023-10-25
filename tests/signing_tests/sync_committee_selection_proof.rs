use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn sync_committee_selection_proof_request() -> BLSSignMsg {
    // Create a SyncCommitteeSelectionAndProof
    let req = mock_sync_committee_selection_proof_request();
    dbg!(&req);
    let signing_data: SyncCommitteeSelectionProofRequest = serde_json::from_str(&req)
        .expect("Failed to serialize mock SyncCommitteeSelectionProofRequest");
    dbg!(&signing_data);
    BLSSignMsg::SYNC_COMMITTEE_SELECTION_PROOF(signing_data)
}

pub fn mock_sync_committee_selection_proof_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "SYNC_COMMITTEE_SELECTION_PROOF",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            }},
            "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "sync_aggregator_selection_data": {{
                "slot": "123123",
                "subcommittee_index": "12345"
            }}
        }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_selection_proof_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_sync_committee_selection_proof_happy_path() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_selection_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_sync_committee_selection_proof_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("84b81f509f9ffb74439a0c862aaafbcb7c6a406bddcb7d5c30b668153a8d86b7a10425bf9e04254ae22e1c9f3dbd5fbe172014c74ee17984e0a90dad03ed31597aabc8d00a78af41f9696aa017f65306154f2dd51f669f12155b7de0269881c0".to_string());
    let req = sync_committee_selection_proof_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);
    let sig = resp.unwrap().signature;
    let got_sig: String = strip_0x_prefix!(sig);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
async fn test_sync_committee_committee_selection_proof_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "SyncAggregatorSelectionData"]
        .iter()
        .collect();
    dbg!(&path);

    let port = common::read_secure_signer_port();
    let req = sync_committee_selection_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    let msgs = eth_specs::get_all_test_vecs("SyncAggregatorSelectionData").unwrap();
    for msg in msgs.into_iter() {
        let (_resp, status) = make_signing_route_request(msg, &bls_pk_hex, port)
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
}
