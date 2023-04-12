use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn randao_reveal_request() -> BLSSignMsg {
    // Create a RandaoRevealRequest
    let req = mock_randao_reveal_request();
    let signing_data: RandaoRevealRequest = serde_json::from_str(&req).unwrap();
    BLSSignMsg::RANDAO_REVEAL(signing_data)
}

pub fn mock_randao_reveal_request() -> String {
    let req = format!(
        r#"
        {{
           "type":"randao_reveal",
           "fork_info":{{
              "fork":{{
                 "previous_version":"0x00000000",
                 "current_version":"0x00000000",
                 "epoch":"2"
              }},
              "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
           }},
           "signingRoot": "0xbf70dbbbc83299fb877334eaeaefb32df44242c1bf078cdc1836dcc3282d4fbd",
           "randao_reveal":{{
                "epoch": "10"
           }}
        }}"#
    );
    req
}
#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = randao_reveal_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_randao_reveal_happy_path() {
    let port = common::read_secure_signer_port();
    let req = randao_reveal_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_randao_reveal_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("a8c5eb481ef1c3ea345bc9cb9ce9918e18ef052d8287bacd3b1e1bbd34bc4e1e016602b778535d5b582bc35ea6d2ded106ea2cfec06f8b6c5bd049dbf0a544207ac3b21c634b8e78c2c0135a0000e961adae192203ef168de1edb83618d1a76d".to_string());
    let req = randao_reveal_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}