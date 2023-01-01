use crate::route_handlers::{
    KeyImportRequest, RemoteAttestationRequest, epid_remote_attestation_service, eth_key_gen_service, 
    list_eth_keys_service, bls_key_gen_service, list_generated_bls_keys_service, 
    bls_key_import_service, list_imported_bls_keys_service, secure_sign_bls, 
};
use warp::Filter;


/// Signs off on validator duty.
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn bls_sign_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("v1"))
        .and(warp::path("eth2"))
        .and(warp::path("sign"))
        .and(warp::path::param())
        .and(warp::body::bytes())
        .and_then(secure_sign_bls)
}
use warp::{http::StatusCode, reply};
/// Returns a 200 status code if server is alive
pub fn upcheck_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("upcheck"))
        .and(warp::any().map(warp::reply))
}

/// Imports a BLS private key to the Enclave. 
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager
pub fn bls_key_import_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and(warp::body::json::<KeyImportRequest>())
        .and_then(bls_key_import_service)
}

/// Returns all hex-encoded BLS public keys, where the private keys were imported and saved in the Enclave.
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager
pub fn list_imported_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_imported_bls_keys_service)
}

/// Performs EPID remote attestation, committing to a public key
/// Route added by Secure-Signer
pub fn epid_remote_attestation_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("remote-attestation"))
        .and(warp::body::json::<RemoteAttestationRequest>())
        .and_then(epid_remote_attestation_service)
}

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned 
/// Route added by Secure-Signer
pub fn eth_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(eth_key_gen_service)
}

/// Returns all hex-encoded ETH public keys, where the private keys were generated and saved in the Enclave.
/// Route added by Secure-Signer
pub fn list_generated_eth_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(list_eth_keys_service)
}

/// Generates a new BLS private key in Enclave. To remain compatible with web3signer POST /eth/v1/keystores, the JSON body is not parsed. The BLS public key is returned 
/// Route added by Secure-Signer
pub fn bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(bls_key_gen_service)
}

/// Returns all hex-encoded BLS public keys, where the private keys were generated and saved in the Enclave.
/// Route added by Secure-Signer
pub fn list_generated_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(list_generated_bls_keys_service)
}


// TODO /upcheck



#[cfg(test)]
mod api_signing_tests {
    use super::*;
    use std::fs;
    use serde_json;
    use crate::eth_signing::slash_resistance_tests::*;
    use crate::route_handlers::mock_requests::*;
    use crate::eth_types::{RandaoRevealRequest, BlockV2Request};

    async fn mock_secure_sign_bls_route(bls_pk: &String, json_req: &String) -> warp::http::Response<bytes::Bytes> {
        let filter = bls_sign_route();
        let uri = format!("/api/v1/eth2/sign/{}", bls_pk);

        println!("mocking request to: {uri}");
        let res = warp::test::request()
            .method("POST")
            .path(&uri)
            .body(&json_req)
            .reply(&filter)
            .await;
        res
    }

    #[tokio::test]
    async fn test_bls_sign_route_block_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for a BLOCK request
        let json_req = mock_propose_block_request("10");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);

        // mock data for a BLOCK request (attempt a slashable offense - non-increasing slot)
        let json_req = mock_propose_block_request("10");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for a BLOCK request (attempt a slashable offense - decreasing slot)
        let json_req = mock_propose_block_request("9");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for a BLOCK request 
        let json_req = mock_propose_block_request("11");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_route_block_v2_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for a BLOCK request
        let json_req = mock_block_v2_bellatrix_request("10");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);

        // mock data for a BLOCK request (attempt a slashable offense - non-increasing slot)
        let json_req = mock_block_v2_bellatrix_request("10");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for a BLOCK request (attempt a slashable offense - decreasing slot)
        let json_req = mock_block_v2_bellatrix_request("9");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for a BLOCK request 
        let json_req = mock_block_v2_bellatrix_request("11");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_route_attestation_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for ATTESTATION request
        let json_req = mock_attestation_request("10", "11");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);

        // mock data for ATTESTATION request (attempt a slashable offense - decreasing source)
        let json_req = mock_attestation_request("0", "12");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for ATTESTATION request (attempt a slashable offense - non-increasing target)
        let json_req = mock_attestation_request("10", "11");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 412);

        // mock data for ATTESTATION request (non-increasing source + increasing target)
        let json_req = mock_attestation_request("10", "12");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);

        // mock data for ATTESTATION request (increasing source + increasing target)
        let json_req = mock_attestation_request("11", "13");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_route_randao_reveal_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for RANDAO_REVEAL request
        let json_req = mock_randao_reveal_request();
        let parsed_req: RandaoRevealRequest = serde_json::from_str(&json_req).unwrap();
        assert_eq!(parsed_req.fork_info.fork.previous_version, [0,0,0,0]);
        assert_eq!(parsed_req.fork_info.fork.current_version, [0,0,0,0]);
        assert_eq!(parsed_req.fork_info.fork.epoch, 0);
        assert_eq!(parsed_req.fork_info.genesis_validators_root, [42_u8; 32]);
        assert_eq!(parsed_req.signingRoot, [191, 112, 219, 187, 200, 50, 153, 251, 135, 115, 52, 234, 234, 239, 179, 45, 244, 66, 66, 193, 191, 7, 140, 220, 24, 54, 220, 195, 40, 45, 79, 189]);
        assert_eq!(parsed_req.randao_reveal.epoch, 0);

        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        println!("{:?}", resp);
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_route_aggregate_and_proof_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for RANDAO_REVEAL request
        let json_req = mock_aggregate_and_proof_request("0", "1");
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        println!("{:?}", resp);
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_route_block_V2_bellatrix_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for RANDAO_REVEAL request
        let json_req = mock_block_v2_bellatrix_request("24000");
        let parsed_req: BlockV2Request = serde_json::from_str(&json_req).unwrap();
        assert_eq!(parsed_req.fork_info.fork.previous_version, [128,0,0,112]);
        assert_eq!(parsed_req.fork_info.fork.current_version, [128,0,0,113]);
        assert_eq!(parsed_req.fork_info.fork.epoch, 750);
        assert_eq!(parsed_req.fork_info.genesis_validators_root, [42_u8; 32]);
        assert_eq!(parsed_req.signingRoot, [46, 191, 194, 215, 9, 68, 204, 47, 191, 246, 214, 124, 109, 156, 187, 4, 61, 127, 190, 10, 102, 13, 36, 139, 110, 102, 108, 225, 16, 175, 65, 138]);
        assert_eq!(parsed_req.beacon_block.block_header.slot, 24000);
        assert_eq!(parsed_req.beacon_block.block_header.proposer_index, 0);
        assert_eq!(parsed_req.beacon_block.block_header.parent_root, [0_u8; 32]);
        assert_eq!(parsed_req.beacon_block.block_header.state_root, [0_u8; 32]);
        assert_eq!(parsed_req.beacon_block.block_header.body_root, [205, 124, 73, 150, 110, 190, 114, 177, 33, 78, 109, 71, 51, 173, 246, 191, 6, 147, 92, 95, 188, 59, 58, 208, 142, 132, 227, 8, 84, 40, 184, 47]);

        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        println!("{:?}", resp);
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_bls_sign_deposit_type() {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // mock data for RANDAO_REVEAL request
        let json_req = mock_deposit_request();
        let resp = mock_secure_sign_bls_route(&bls_pk_hex, &json_req).await;
        println!("{:?}", resp);
        assert_eq!(resp.status(), 200);
    }

    
    // todo
    // async fn test_bls_sign_route_aggregation_slot_type() {}
    // async fn test_bls_sign_route_sync_committee_message_type() {}
    // async fn test_bls_sign_route_sync_committee_selection_proof_type() {}
    // async fn test_bls_sign_route_sync_committee_contribution_and_proof_type() {}

}


#[cfg(test)]
mod key_management_tests {
    use super::*;
    use crate::keys::{new_bls_key, new_eth_key, CIPHER_SUITE, eth_pk_from_hex};
    use crate::remote_attesation::{AttestationEvidence, fetch_dummy_evidence};
    use crate::routes::*;
    use crate::route_handlers::*;
    use ecies::{decrypt, encrypt};
    use blst::min_pk::{SecretKey, PublicKey, Signature};
    use ecies::PublicKey as EthPublicKey;
    use ecies::SecretKey as EthSecretKey;
    use std::collections::HashMap;
    use std::fs;
    use serde_json;

    async fn call_eth_key_gen_route() -> KeyGenResponse {
        let filter = eth_key_gen_route();

        // mock the request
        let res = warp::test::request()
            .method("POST")
            .path("/eth/v1/keygen/secp256k1")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);

        // parse the resp
        let resp: KeyGenResponse = serde_json::from_slice(&res.body()).unwrap();
        resp
    }

    async fn mock_request_eth_key_list_route() -> ListKeysResponse {
        let filter = list_generated_eth_keys_route();
        let res = warp::test::request()
            .method("GET")
            .path("/eth/v1/keygen/secp256k1")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);
        let resp: ListKeysResponse = serde_json::from_slice(&res.body()).unwrap();
        resp
    }

    #[tokio::test]
    async fn test_call_eth_key_gen_route() {
        fs::remove_dir_all("./etc");
        let resp = call_eth_key_gen_route().await;
        println!("resp: {:?}", resp);

        let list_keys_resp = mock_request_eth_key_list_route().await;
        println!("resp: {:?}", list_keys_resp);
        assert_eq!(list_keys_resp.data.len(), 1);
        assert_eq!(list_keys_resp.data[0].pubkey, resp.pk_hex);
    }

    async fn mock_request_bls_key_import_route() -> KeyImportResponse {
        // 1) generate ETH secret key in enclave
        let resp = call_eth_key_gen_route().await;
        let enclave_eth_pk_hex = resp.pk_hex;
        let eth_pk = eth_pk_from_hex(enclave_eth_pk_hex.clone()).unwrap();
        let enclave_eth_pk_bytes = eth_pk.serialize_compressed();

        // 2) request enclave to do remote attestation
        // let resp = enclave_remote_attestation();

        // 3) verify evidence
        // ...

        // 4) extract ETH pub key
        // ...

        // 5) locally generate BLS key to import
        let bls_sk = new_bls_key().unwrap();

        // 6) encrypt BLS key with ETH pub key
        let ct_bls_sk = encrypt(&enclave_eth_pk_bytes, &bls_sk.serialize()).unwrap();
        let ct_bls_sk_hex = hex::encode(ct_bls_sk);
        let bls_pk_hex = "0x".to_string() + &hex::encode(bls_sk.sk_to_pk().compress()); // 48 bytes

        // 7) make payload to send /eth/v1/keystores POST request
        let req = KeyImportRequest {
            ct_bls_sk_hex: ct_bls_sk_hex,
            bls_pk_hex: bls_pk_hex.clone(),
            encrypting_pk_hex: enclave_eth_pk_hex.clone(),
        };
        println!("making bls key import req: {:?}", req);

        // 8) make the actual request
        let filter = bls_key_import_route();
        let res = warp::test::request()
            .method("POST")
            .header("accept", "application/json")
            .path("/eth/v1/keystores")
            .json(&req)
            .reply(&filter)
            .await;


        println!("{:?}", res.body());
        assert_eq!(res.status(), 200);

        let resp: KeyImportResponse = serde_json::from_slice(&res.body()).unwrap();

        assert_eq!(resp.data[0].status, "imported".to_string());
        assert_eq!(resp.data[0].message, bls_pk_hex);
        resp
    }


    #[tokio::test]
    async fn test_request_bls_key_import_route() {
        fs::remove_dir_all("./etc");
        let resp = mock_request_bls_key_import_route().await;
        println!("{:?}", resp);
    }

    async fn mock_request_bls_key_list_route() -> ListKeysResponse {
        let filter = list_imported_bls_keys_route();
        let res = warp::test::request()
            .method("GET")
            .path("/eth/v1/keystores")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);
        let resp: ListKeysResponse = serde_json::from_slice(&res.body()).unwrap();
        resp
    }

    #[tokio::test]
    async fn test_list_imported_bls_keys_route() {
        // clear any existing local keys
        fs::remove_dir_all("./etc");
        let key_gen_resp = mock_request_bls_key_import_route().await;
        println!("key_gen_resp {:?}", key_gen_resp);
        let bls_pk_hex = key_gen_resp.data[0].message.clone();
        assert_eq!(key_gen_resp.data.len(), 1);

        let list_keys_resp = mock_request_bls_key_list_route().await;
        assert_eq!(list_keys_resp.data.len(), 1);
        assert_eq!(list_keys_resp.data[0].pubkey, bls_pk_hex);
    }


    async fn mock_request_bls_key_gen_route() -> KeyGenResponse {
        let filter = bls_key_gen_route();
        let res = warp::test::request()
            .method("POST")
            .path("/eth/v1/keygen/bls")
            .reply(&filter)
            .await;

        println!{"{:?}", res.body()};
        assert_eq!(res.status(), 200);

        let resp: KeyGenResponse = serde_json::from_slice(&res.body()).unwrap();

        resp
    }

    async fn mock_request_generated_bls_key_list_route() -> ListKeysResponse {
        let filter = list_generated_bls_keys_route();
        let res = warp::test::request()
            .method("GET")
            .path("/eth/v1/keygen/bls")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);
        let resp: ListKeysResponse = serde_json::from_slice(&res.body()).unwrap();
        resp
    }

    #[tokio::test]
    async fn test_bls_key_gen_route() {
        // clear any existing local keys
        fs::remove_dir_all("./etc");
        let key_gen_resp = mock_request_bls_key_gen_route().await;
        let bls_pk_hex = key_gen_resp.pk_hex.clone();

        let list_keys_resp = mock_request_generated_bls_key_list_route().await;
        assert_eq!(list_keys_resp.data.len(), 1);
        assert_eq!(list_keys_resp.data[0].pubkey, bls_pk_hex);
    }
}
