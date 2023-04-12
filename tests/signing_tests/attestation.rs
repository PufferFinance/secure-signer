use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

const START_SRC_EPOCH: u64 = 1234;
const START_TGT_EPOCH: u64 = 1235;

fn attestation_req(
    src_epoch: u64,
    tgt_epoch: u64,
) -> BLSSignMsg {
    // Create AttestationRequest
    let req = mock_attestation_request(src_epoch, tgt_epoch);
    let signing_data: AttestationRequest = serde_json::from_str(&req).unwrap();
    BLSSignMsg::ATTESTATION(signing_data)
}

fn mock_attestation_request(src_epoch: u64, tgt_epoch: u64) -> String {
    let req = format!(
        r#"
        {{
            "type": "ATTESTATION",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x00000001",
                   "current_version":"0x00000001",
                   "epoch":"0"
                }},
                "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }},
            "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
            "attestation": {{
                "slot": "255",
                "index": "65535",
                "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                "source": {{
                    "epoch": "{src_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }},
                "target": {{
                    "epoch": "{tgt_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }}
            }}
        }}"#
    );
    req
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_attestation_happy_path() {
    let port = common::read_secure_signer_port();
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_attestation_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("80f9bc73528e2025e8514c89ba468dbe48e8154795c5822fc59c7c3f8982a29a9c5456c87ccdb86765b2759802749fa411c0c52ed542b717a590f77cddafd774d17e94de720f0c21b12d10c969b5141ebad17cffd4af5addec4f8882a200ebf1".to_string());
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
pub async fn test_slash_protection_allows_non_slashable_attestation() {
    let port = common::read_secure_signer_port();
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // valid ATTESTATION request (non-decreasing source + increasing target)
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH + 1);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_slash_protection_prevents_decreasing_source() {
    let port = common::read_secure_signer_port();
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // mock data for ATTESTATION request (attempt a slashable offense - decreasing source)
    let req = attestation_req(0, START_TGT_EPOCH + 1);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 412);
}

#[tokio::test]
pub async fn test_slash_protection_prevents_same_target() {
    let port = common::read_secure_signer_port();
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // mock data for ATTESTATION request (attempt a slashable offense - non-increasing target)
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 412);
}

#[tokio::test]
pub async fn test_slash_protection_prevents_decreasing_target() {
    let port = common::read_secure_signer_port();
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);

    // mock data for ATTESTATION request (attempt a slashable offense - non-increasing target)
    let req = attestation_req(START_SRC_EPOCH, START_TGT_EPOCH - 1);
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 412);
}

#[tokio::test]
async fn test_attestation_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "Attestation"].iter().collect();
    dbg!(&path);
    let msgs = eth_specs::get_all_test_vecs("Attestation").unwrap();

    let port = common::read_secure_signer_port();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;

    let mut src: Epoch = 0;
    let mut tgt: Epoch = 0;
    let mut last_src: Epoch = 0;
    let mut last_tgt: Epoch = 0;
    let mut slashable = false;
    for msg in msgs.into_iter() {
        if let BLSSignMsg::ATTESTATION(msg) = &msg {
            src = msg.attestation.source.epoch;
            tgt = msg.attestation.target.epoch;
            if src < last_src || tgt <= last_tgt {
                slashable = true;
            }
        }

        let (status, _resp) = make_signing_route_request(msg, &bls_pk_hex, port).await;

        if slashable {
            assert_eq!(status, 412);
            slashable = false;
        } else {
            assert_eq!(status, 200);
            last_src = src;
            last_tgt = tgt;
        }
    }
}
