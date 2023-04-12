use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

const START_SLOT: u64 = 1234;

fn block_proposal_request(slot: u64) -> BLSSignMsg {
    // Create a BlockRequest
    let req = mock_propose_block_v2_request(slot);
    let signing_data: BlockV2Request = serde_json::from_str(&req).unwrap();
    BLSSignMsg::BLOCK_V2(signing_data)
}

pub fn mock_propose_block_v2_request(slot: u64) -> String {
    let req = format!(
        r#"
        {{
            "type": "BLOCK_V2",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
             }},
             "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "beacon_block": {{
                "version": "BELLATRIX",
                "block_header": {{
                    "slot": "{slot}",
                    "proposer_index": "0",
                    "parent_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    "state_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body_root":"0xcd7c49966ebe72b1214e6d4733adf6bf06935c5fbc3b3ad08e84e3085428b82f"
                }}
            }}
        }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_block_v2_happy_path() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_block_v2_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("b0eb25ae2c2df6f3089953596341912ec3137457088c5ba57be9f326a647b9e60a931a0971e68f27c1bbe6d5a100c58e0518691357c047851fc2db686d681c65acc3000d218c64f036fbf68d028d840e775d805ccadba4f6fcf1b099bcd63117".to_string());
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
pub async fn test_aggregate_block_v2_slash_protection_allows_increasing_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // valid BLOCK request (increasing slot)
    let req = block_proposal_request(START_SLOT + 1);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_block_slash_protection_prevents_duplicate_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // mock data for BLOCK request (attempt a slashable offense - non-increasing source)
    let req = block_proposal_request(START_SLOT);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 412);
}

#[tokio::test]
pub async fn test_aggregate_block_slash_protection_prevents_decreasing_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // mock data for BLOCK request (attempt a slashable offense - decreasing source)
    let req = block_proposal_request(START_SLOT - 1);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 412);
}

#[tokio::test]
async fn test_block_v_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "BeaconBlockHeader"].iter().collect();
    dbg!(&path);
    let msgs = eth_specs::get_all_test_vecs("BeaconBlockHeader").unwrap();

    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    let mut slot: Slot = 0;
    let mut last_slot: Slot = 0;
    let mut slashable = false;
    for msg in msgs.into_iter() {
        if let BLSSignMsg::BLOCK_V2(msg) = &msg {
            slot = msg.beacon_block.block_header.slot;
            if slot <= last_slot {
                slashable = true;
            }
        }
        let (status, _resp) = make_signing_route_request(msg, &bls_pk_hex, port).await;

        if slashable {
            assert_eq!(status, 412);
            slashable = false;
        } else {
            assert_eq!(status, 200);
            last_slot = slot;
        }
    }
}
