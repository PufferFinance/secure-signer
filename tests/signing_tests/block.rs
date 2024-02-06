use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::{eth_specs, signing_helper::*};
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;
use std::path::PathBuf;

use ethers::utils::hex;

const START_SLOT: u64 = 1234;

fn block_proposal_request(slot: u64) -> BLSSignMsg {
    // Create a BlockRequest
    let req = mock_propose_block_request(slot);
    let signing_data: BlockRequest = serde_json::from_str(&req).unwrap();
    BLSSignMsg::BLOCK(signing_data)
}

fn mock_propose_block_request(slot: u64) -> String {
    let req = format!(
        r#"
            {{
               "type":"BLOCK",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x03000000",
                     "current_version":"0x04000000",
                     "epoch":"18446744073709551615"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "block":{{
                  "slot":"{slot}",
                  "proposer_index":"203632848322298003",
                  "parent_root":"0x345180d51e713558f5c04441885f66c7efae7049f131514e242e1a425e82a33a",
                  "state_root":"0x7d4e56330757f74b85780a681071a1fc739677b31bb8e6de1883c7223c0cf004",
                  "body":{{
                     "randao_reveal":"0x52d707dad4fe816193f3c750fd0364239c3b016d93bfc6ed6d6942aaf2d7f40c13530e74d4b8caeaf63226048f9980178f657f80814ad89c3927ffc09ce645db584431c28e0062592e8feb286c26a6d8fdbc10b76fef39b1f027ac9f75875afb",
                     "eth1_data":{{
                        "deposit_root":"0x07e0f0099cca08952245ca80c38b47f416fe04680c848014f51db5082a9b4dae",
                        "deposit_count":"5926170773549472594",
                        "block_hash":"0xed508ba9402be6e160289a5c7cb26bb4655a3c8892e08683d591459b850a26e3"
                     }},
                     "graffiti":"0xc08b7f248d521f738a30a59ea853e29a44e3fb7f922e71300953ffaf7e433c84",
                     "proposer_slashings":[],
                     "attester_slashings":[],
                     "attestations":[],
                     "deposits":[],
                     "voluntary_exits":[],
                     "sync_aggregate":{{
                        "sync_committee_bits": "0x394ad3147af5791bb140916cd739e2fb42227a3328ef549273cddd844d03fdaac1a561e661b3bea7b17090e65804c4808c616e243bfcc9cae07601580ddf4e76",
                        "sync_committee_signature": "0x682c238dc9245d4ffdba2124479d271ca37be4f9093e24cd3b96a62e781d7db43c7e224f019fcd352193a528635a3a7942c950e68ef2816834e656149ce9c5b4f466e2d82792e6a98ef93d85d3b10fdb5a3a8e3c6ea73dcbe31c8c0e3464faa1"
                     }},
                     "execution_payload": {{
                        "parent_hash": "0x373871c33ef228eff82e981251f3c2205160abd1a7f5aa7cd4d14e1a0adaa20c",
                        "fee_recipient": "0x153dd4157d440d020602574e11e9b03c768f94e1",
                        "state_root": "0xba15541d19d6f976e9cda6d8b79ead92a43481672353228d5d2ef7f01e4edcd2",
                        "receipts_root": "0x7748c0581ee935bf81c5b344934263eafa392fe7567281b3b398eea383ee8d50",
                        "logs_bloom": "0x9de3c13e464897d07c3c0ed3342112b2ec7cff59f679dc2992d64ecaee469d7de9290dc29dab5425e766f89d40da0dbeac4e83529d5f82d781e656d9a0f48b576e19593d77c9611c875b480a79c54516a2d8d854d135c8e963ef6bf5d3d44e80be898f3bb4ff9f75f85471cb4dd4daec1cf8d7548ed48a23bf85e74918492368579b03188e8787d89f75ae5d869ce785bb79c18cb4e524d7f861b27866bac87aaf47b0413410be9dda30c9de6edabe9a17ed1ad8696c392b978dadc81cb5a858872ac04967616906339adf8ec89688fbe0e0cdde920aabd57bde1ade24b05ac84ca2c416272efa236cbedc618d8fc67098614375b7a55ed7f031ba5edea312ab",
                        "prev_randao": "0xeeea4ee9d040398830e5c822657f892acaa844a6141be434ccf39c89de3f1904",
                        "block_number": "13939382931671148224",
                        "gas_limit": "14388568890001640822",
                        "gas_used": "2577702994545812206",
                        "timestamp": "2577702994545812206",
                        "extra_data": "0x63ed0a39af88cc79efe44fc7a677",
                        "base_fee_per_gas": "34591868959907565691726467724468583992047712261299446221682432921156757610262",
                        "block_hash": "0xf41a6c0aad360116873c7135c892da79e116b0674511aca772a34a67765b518e",
                        "transactions": [],
                        "withdrawals": [],
                        "excess_data_gas": "98720436696999082086586182109704008989462229285798660257384133327308163542124"
                     }},
                     "bls_to_execution_changes": [],
                     "blob_kzg_commitments": []
                  }}
               }},
               "signingRoot": "0xaffb8a55ef3f26b7126201b1bb470c9c906304e0685ac1656e3f96ac94ab2d63"
            }}"#
    );
    req
}

#[tokio::test]
pub async fn print_signing_root() {
  let req = block_proposal_request(START_SLOT); 
  println!("{:?}", hex::encode(req.to_signing_root(None)));
}

#[tokio::test]
pub async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 400);
}

#[tokio::test]
pub async fn test_aggregate_block_happy_path() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_block_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("a156ad93565d3a5d9e79f36a55f335a9c589d6428613ef067620d50185121f7b6ab8e54acc86d67a66c0addb25107c5509f6f35cc1f98651c24c673227197d98dcfd9a93e9672d19b37c25c8b1ccefad70ca42052dd76e3b59713c074ddf4d22".to_string());
    let req = block_proposal_request(START_SLOT);
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
pub async fn test_slash_protection_allows_increasing_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    // valid BLOCK request (increasing slot)
    let req = block_proposal_request(START_SLOT + 1);
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_slash_protection_prevents_duplicate_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    // mock data for BLOCK request (attempt a slashable offense - non-increasing slot)
    let req = block_proposal_request(START_SLOT);
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 412);
}

#[tokio::test]
pub async fn test_slash_protection_prevents_decreasing_slot() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    // mock data for BLOCK request (attempt a slashable offense - decreasing slot)
    let req = block_proposal_request(START_SLOT - 1);
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 412);
}

async fn perf_test(n: u64, bls_pk_hex: &String, port: Option<u16>) {
    for i in 1..n {
        let req = block_proposal_request(i);
        let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
}

#[tokio::test]
pub async fn perf_tester() {
    let n = 1000;
    let port = common::read_secure_signer_port();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    perf_test(n, &bls_pk_hex, port).await;
}

#[tokio::test]
async fn test_block_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "BeaconBlock"].iter().collect();
    dbg!(&path);
    let msgs = eth_specs::get_all_test_vecs("BeaconBlock").unwrap();

    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (_resp, status) = make_signing_route_request(req, &bls_pk_hex, port)
        .await
        .unwrap();
    assert_eq!(status, 200);

    let mut slot: Slot = 0;
    let mut last_slot: Slot = 0;
    let mut slashable = false;
    for msg in msgs.into_iter() {
        if let BLSSignMsg::BLOCK(msg) = &msg {
            slot = msg.block.slot;
            if slot <= last_slot {
                slashable = true;
            }
        }

        let (_resp, status) = make_signing_route_request(msg, &bls_pk_hex, port)
            .await
            .unwrap();

        if slashable {
            assert_eq!(status, 412);
            slashable = false;
        } else {
            assert_eq!(status, 200);
            last_slot = slot;
        }
    }
}
