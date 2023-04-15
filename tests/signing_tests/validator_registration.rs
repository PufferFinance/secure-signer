use crate::common;
use crate::common::bls_keygen_helper::register_new_bls_key;
use crate::common::signing_helper::*;
use puffersecuresigner::eth2::eth_signing::*;
use puffersecuresigner::eth2::eth_types::*;
use puffersecuresigner::strip_0x_prefix;

fn validator_registration_request() -> BLSSignMsg {
    // Create a ValidatorRegistrationRequest
    let req = mock_validator_registration_request();
    dbg!(&req);
    let signing_data: ValidatorRegistrationRequest =
        serde_json::from_str(&req).expect("Failed to serialize mock ValidatorRegistrationRequest");
    dbg!(&signing_data);
    BLSSignMsg::VALIDATOR_REGISTRATION(signing_data)
}

pub fn mock_validator_registration_request() -> String {
    let req = format!(
        r#"
        {{
            "type": "VALIDATOR_REGISTRATION",
            "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
            "validator_registration": {{
                "fee_recipient": "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "gas_limit": "30000000",
                "timestamp":"100",
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18"
            }}
        }}"#
    );
    req
}

#[tokio::test]
async fn test_aggregate_route_fails_from_invalid_pk_hex() {
    let port = common::read_secure_signer_port();
    let req = validator_registration_request();
    let bls_pk_hex = "0xdeadbeef".to_string();
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn test_aggregate_validator_registration_happy_path() {
    let port = common::read_secure_signer_port();
    let req = validator_registration_request();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    let (status, _resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn test_aggregate_validator_registration_happy_path_test_vec() {
    let port = None;
    let exp_sig = Some("8dc27307e86e464e1eb09247a127cf728df3bdf38bc6871a909a955da178ace5ad3b9087013b0bd24d8af57fb4e5f90f103d200a3e06b4cd56fa780bceac878425de9415f3f947cb279ef9f83141a4c7757100cba5314ac1c0f3dc9b1d92efd5".to_string());
    let req = validator_registration_request();
    let bls_pk_hex = common::setup_dummy_keypair();
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex, port).await;
    assert_eq!(status, 200);
    let got_sig: String = strip_0x_prefix!(resp.as_ref().unwrap().signature);
    assert_eq!(exp_sig.unwrap(), got_sig);
}
