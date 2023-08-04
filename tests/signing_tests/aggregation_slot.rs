use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::signing_helper::*;
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;

fn aggregation_slot_request() -> BLSSignMsg {
    // Create an AggregationSlotRequest
    let req = mock_aggregation_slot_request();
    let signing_data: AggregationSlotRequest = serde_json::from_str(&req).unwrap();
    dbg!(&signing_data);
    BLSSignMsg::AGGREGATION_SLOT(signing_data)
}

pub fn mock_aggregation_slot_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "AGGREGATION_SLOT",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            }},
            "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "aggregation_slot": {{
                "slot": "123123"
            }}
        }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = aggregation_slot_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_aggregation_slot_happy_path() {
    let port = common::read_secure_signer_port();
    let req = aggregation_slot_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_aggregation_slot_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("84eaf231b6b98cafebf914888d98a5239ee69b338b2aa6f87d9c7ecf7f602644ffb75f78bc91fe48b85ae6df660a48e916aef96677b809436b0504fe3e85c22b79d686eb46787ffc0a4d37cbdb1ba45f5c8e22d1e43e6429eb151d3099ff1cdb".to_string());
    let req = aggregation_slot_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}
