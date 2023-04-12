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
                     "previous_version":"0x00000001",
                     "current_version":"0x00000001",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "block":{{
                  "slot":"{slot}",
                  "proposer_index":"5",
                  "parent_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
                  "state_root":"0x2b530d6262576277f1cc0dbe341fd919f9f8c5c92fc9140dff6db4ef34edea0d",
                  "body":{{
                     "randao_reveal":"0xa686652aed2617da83adebb8a0eceea24bb0d2ccec9cd691a902087f90db16aa5c7b03172a35e874e07e3b60c5b2435c0586b72b08dfe5aee0ed6e5a2922b956aa88ad0235b36dfaa4d2255dfeb7bed60578d982061a72c7549becab19b3c12f",
                     "eth1_data":{{
                        "deposit_root":"0x6a0f9d6cb0868daa22c365563bb113b05f7568ef9ee65fdfeb49a319eaf708cf",
                        "deposit_count":"8",
                        "block_hash":"0x4242424242424242424242424242424242424242424242424242424242424242"
                     }},
                     "graffiti":"0x74656b752f76302e31322e31302d6465762d6338316361363235000000000000",
                     "proposer_slashings":[],
                     "attester_slashings":[],
                     "attestations":[],
                     "deposits":[],
                     "voluntary_exits":[],
                     "sync_aggregate":{{
                        "sync_committee_bits": "0x2c7f40a82adc635225137e8f0c26ae6b59622ca52038a5257c08d922c30e509be5026c8fe7446cb718e6dc89a82ae746151302558a94509e48e269ff0a2ab412",
                        "sync_committee_signature": "0x0593c71c45ffa7d7370364f385976716933263d3adb568a5d91bbf5ce614f3a775c4f824c0d5cbd6e095bbacb1a1894d34a651d3a805a7e7c65e124f7bf824a59fe74363025c64795d51d483f3f470f5a03bf13998c85a734d90a1badbd3ef44"
                     }},
                     "execution_payload": {{
                        "parent_hash": "0x8c6a98f2c7fec600d906dff714fed34e60ceb42aae514e64e94f8d0fa3357db5",
                        "fee_recipient": "0x6ddc050451366ece5a256f914de3ef2aabae4f64",
                        "state_root": "0x84af0b08204705cf38a9250ca820a21b96d24be093aca64af81df2cecebce8c0",
                        "receipts_root": "0x01545bf1040bb814a82a84331abaf583c791eb4014d6f779785ebf71cc1ebe90",
                        "logs_bloom": "0xa32e2246859ee9020ce96e9ba280b414fbd2106860bc9dc81e072b8955243fc0dd0d6f1cb27092ee40b659be4fc96ca90e20a18154b17f767746e4d9ce1a4127d2992a9b3cdbcd229626410ee28d4334e53136f3fdea8e7dc972a34575f19dee0eb89e3c24503eee8bc39aba26628c277bb308550b584cf06859b60bd16fadb863cd86548caf801bb4db9cb7081c6f401fef35fde98d8823ea510f841b0b08196b901ca7e61dba5ef110f14b3b23f5fc0fd8e1395bfaefc007d2a51c4a3ff19c0177cb6c4157a86c2748a9ac8b195cd21a881837eb9cc78d0b97c52b53c872efe306082d7ea055ef926bf750b5c4f90a406daf203bf07e17a981295725f4244b",
                        "prev_randao": "0x1366d1430de25c4abd0602135d2338db0af1a579be1cc85289a84bf7020c4c2c",
                        "block_number": "17395900384505305257",
                        "gas_limit": "2812759721706978498",
                        "gas_used": "5752497322817586769",
                        "timestamp": "1003778503642348003",
                        "extra_data": "0xf859bae9ccaa5e467dcdc221bde85221b958a74d64877582",
                        "base_fee_per_gas": "63708707529687817917533240047805124624724989221198991928642968237818118949448",
                        "block_hash": "0xbf1c54ffb22a32cf786636b80b8dc691673208a372af25bfe8380517083ee3c4",
                        "transactions": [],
                        "withdrawals": []
                     }},
                     "bls_to_execution_changes": []
                  }}
               }},
               "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
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
pub async fn test_aggregate_block_happy_path() {
    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
pub async fn test_aggregate_block_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("a156ad93565d3a5d9e79f36a55f335a9c589d6428613ef067620d50185121f7b6ab8e54acc86d67a66c0addb25107c5509f6f35cc1f98651c24c673227197d98dcfd9a93e9672d19b37c25c8b1ccefad70ca42052dd76e3b59713c074ddf4d22".to_string());
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}

#[tokio::test]
pub async fn test_slash_protection_allows_increasing_slot() {
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
pub async fn test_slash_protection_prevents_duplicate_slot() {
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
pub async fn test_slash_protection_prevents_decreasing_slot() {
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
async fn test_block_eth2_specs() {
    let path: PathBuf = [eth_specs::BASE_DIR, "BeaconBlock"].iter().collect();
    dbg!(&path);
    let msgs = eth_specs::get_all_test_vecs("BeaconBlock").unwrap();

    let port = common::read_secure_signer_port();
    let req = block_proposal_request(START_SLOT);
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
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
