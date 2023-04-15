use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn deposit_request() -> BLSSignMsg {
    // Create a DepositRequest
    let req = mock_deposit_request();
    dbg!(&req);
    let signing_data: DepositRequest =
        serde_json::from_str(&req).expect("Failed to serialize mock DepositRequest");
    dbg!(&signing_data);
    BLSSignMsg::DEPOSIT(signing_data)
}

pub fn mock_deposit_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "DEPOSIT",
            "genesis_fork_version":"00001020",
            "deposit": {{
                "pubkey": "0x8996c1117cb75927eb53db74b25c3668c0f7b08d34cdb8de1062bef578fb1c1e32032e0555e9f5be47cd5e8f0f2705d5",
                "withdrawal_credentials": "0x75362a41a82133d71eee01e602ad564c73590557bb7c994cf9be5620d2023a58",
                "amount":"32000000000"
            }}
        }}"#
    );
    req
}

#[tokio::test]
async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = deposit_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn test_aggregate_deposit_happy_path() {
    let port = common::read_secure_signer_port();
    let req = deposit_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn test_aggregate_deposit_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("82cc787865c0fb7147fe7350dd5a71f5d92c6a1771eb951826f6b339a319e1904a2310d5d3cbc5e2d0e5f35f2bfe6da5164c33114663222d4238a43d495876dae873dc6af338c4af4f6dbe1ae181331581bdcd353509a2356977b6625c9ab0e5".to_string());
    let req = deposit_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
async fn test_sync_committee_message_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "DepositMessage"].iter().collect();
    dbg!(&path);
    let port = common::read_secure_signer_port();
    let req = deposit_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let msgs = eth_specs::get_all_test_vecs("DepositMessage").unwrap();
    for msg in msgs.into_iter() {
        let (status, _resp) = make_signing_route_request(msg, &bls_pk_hex, port).await;
        assert_eq!(status, 200);
    }
}
