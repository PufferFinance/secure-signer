use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

fn aggregate_and_proof_request() -> BLSSignMsg {
    // Create an AggregateAndProofRequest
    let req = mock_aggregate_and_proof_request();
    let signing_data: AggregateAndProofRequest = serde_json::from_str(&req).unwrap();
    BLSSignMsg::AGGREGATE_AND_PROOF(signing_data)
}

pub fn mock_aggregate_and_proof_request() -> String {
    let req = format!(
        r#"
            {{
               "type":"AGGREGATE_AND_PROOF",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x00000001",
                     "current_version":"0x00000001",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
               "aggregate_and_proof":{{
                    "aggregator_index": "5",
                    "aggregate": {{
                        "aggregation_bits": "0x1234",
                        "data": {{
                            "slot": "750",
                            "index": "1",
                            "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                            "source": {{
                                "epoch": "10",
                                "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                            }},
                            "target": {{
                                "epoch": "12",
                                "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                            }}
                        }},
                        "signature": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                    }},
                    "selection_proof": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }}
            }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = aggregate_and_proof_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_aggregate_and_proof_happy_path() {
    let port = common::read_secure_signer_port();
    let req = aggregate_and_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_aggregate_and_proof_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("81e56af6c3b9f0ce1c7fd3545a3d689fc2edd2c9dd5451ea5f345cc57d74de76ed940e373fdccc76150e643edc57bdb0145ad3770d9207164484f86f746fb26f889833106e3e17cd49572eb7938a9e4502bba99c3234f32695f73ef3ed18bb51".to_string());
    let req = aggregate_and_proof_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
async fn test_aggregate_and_proof_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "AggregateAndProof"].iter().collect();
    dbg!(&path);
    let port = common::read_secure_signer_port();
    let req = aggregate_and_proof_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    let msgs = eth_specs::get_all_test_vecs("AggregateAndProof").unwrap();
    for msg in msgs.into_iter() {
        let (status, _resp) = make_signing_route_request(msg, &bls_pk_hex, port).await;
        assert_eq!(status, 200);
    }
}
