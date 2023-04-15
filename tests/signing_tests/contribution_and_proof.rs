use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn sync_committee_contribution_and_proof_request() -> BLSSignMsg {
    // Create a SyncCommitteeContributionAndProofRequest
    let req = mock_sync_committee_contribution_and_proof_request();
    dbg!(&req);
    let signing_data: SyncCommitteeContributionAndProofRequest = serde_json::from_str(&req)
        .expect("Failed to serialize mock SyncCommitteeContributionAndProofRequest");
    dbg!(&signing_data);
    BLSSignMsg::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(signing_data)
}

/// aggregation bits must be 128b
fn mock_sync_committee_contribution_and_proof_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            }},
            "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "contribution_and_proof": {{
                "aggregator_index": "123123",
                "selection_proof": "0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea",
                "contribution" : {{
                    "slot": "123123",
                    "beacon_block_root": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
                    "subcommittee_index": "12345",
                    "aggregation_bits": "0x00000000000000000000000000000000",
                    "signature": "0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea"
                }}
            }}
        }}"#
    );
    req
}

#[tokio::test]
async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_contribution_and_proof_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn test_aggregate_sync_committee_contribution_and_proof_happy_path() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_contribution_and_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn test_aggregate_sync_committee_contribution_and_proof_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("ae7248f762bf491101f3621bb0b1c85dd2264cdec4ebfcc4774c41d41229123728046722e16cf676742a1ac32b1d3d7611042c5d0e5b813d8c71477ccd2e1a4264a66eb3eb3d58b68641c592f210650c0e182357acf1dde03be8fda1011377b3".to_string());
    let req = sync_committee_contribution_and_proof_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
async fn test_sync_committee_contribution_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "ContributionAndProof"]
        .iter()
        .collect();
    dbg!(&path);

    let port = common::read_secure_signer_port();
    let req = sync_committee_contribution_and_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    let msgs = eth_specs::get_all_test_vecs("ContributionAndProof").unwrap();
    for msg in msgs.into_iter() {
        let (status, _resp) = make_signing_route_request(msg, &bls_pk_hex, port).await;
        assert_eq!(status, 200);
    }
}
