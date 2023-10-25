use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn sync_committee_message_request() -> BLSSignMsg {
    // Create a SyncCommitteeMessageRequest
    let req = mock_sync_committee_message_request();
    dbg!(&req);
    let signing_data: SyncCommitteeMessageRequest =
        serde_json::from_str(&req).expect("Failed to serialize mock SyncCommitteeMessageRequest");
    dbg!(&signing_data);
    BLSSignMsg::SYNC_COMMITTEE_MESSAGE(signing_data)
}

pub fn mock_sync_committee_message_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "sync_committee_message",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            }},
            "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "sync_committee_message": {{
                "slot": "123123",
                "beacon_block_root": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a"
            }}
        }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_message_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_sync_committee_message_happy_path() {
    let port = common::read_secure_signer_port();
    let req = sync_committee_message_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_sync_committee_message_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("8b3c0f3cb3427a6009ee7d2f6691480fcf93d21fc7231d333b0bf997e7fe147f0700e61f4790246ce5650a8510374f3d0d14286e41943a80f30dd9cfc197155f0e8cd4f4ced1f1f2b37214fa146640f59f0b7d59cf61980166287083936eea30".to_string());
    let req = sync_committee_message_request();
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
async fn test_sync_committee_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "SyncCommitteeMessage"]
        .iter()
        .collect();
    dbg!(&path);

    let port = common::read_secure_signer_port();
    let req = sync_committee_message_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    let msgs = eth_specs::get_all_test_vecs("SyncCommitteeMessage").unwrap();
    for msg in msgs.into_iter() {
        let (_resp, status) = make_signing_route_request(msg, &bls_pk_hex, port)
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
}
