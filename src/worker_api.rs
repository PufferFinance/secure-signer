use anyhow::{Result, Context, bail};
use blst::min_pk::SecretKey;
use ecies::decrypt;
use warp::{reply, Filter, http::Response, http::StatusCode};
use crate::attest::fetch_dummy_evidence;
use crate::datafeed::{get_btc_price_feed, get_request, post_request, post_request_no_body};
use crate::common_api::{KeyProvisionRequest, KeyProvisionResponse, ListKeysResponse, KeyGenResponse, KeyImportRequest, KeyImportResponse};
use crate::keys::{eth_key_gen, pk_to_eth_addr, read_eth_key, new_eth_key, write_key};

use std::collections::HashMap;


/// Makes a Reqwest GET request to the Leader's `list_generated_bls_keys_route` route to get a ListKeysResponse.
pub async fn list_generated_bls_keys_get_request() -> Result<ListKeysResponse> {
    let url = format!("http://localhost:3030/portal/v1/keygen/bls");
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<ListKeysResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

/// Handles errors and prepares an http response for running `list_generated_bls_keys_get_request`
pub async fn list_generated_bls_keys_request() -> Result<impl warp::Reply, warp::Rejection> {
    match list_generated_bls_keys_get_request().await {
        Ok(resp) => {
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


/// Makes a Reqwest GET request to the Leader's `bls_key_gen_route` route to get a KeyGenResponse.
pub async fn bls_key_gen_get_request() -> Result<KeyGenResponse> {
    let url = format!("http://localhost:3030/portal/v1/keygen/bls");
    let resp = post_request_no_body(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<KeyGenResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

/// Handles errors and prepares an http response for running `bls_key_gen_get_request`
pub async fn bls_key_gen_request() -> Result<impl warp::Reply, warp::Rejection> {
    match bls_key_gen_get_request().await {
        Ok(resp) => {
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

pub async fn bls_key_gen_provision_post_request(body: KeyProvisionRequest) -> Result<KeyProvisionResponse> {
    let url = format!("http://localhost:3030/portal/v1/provision");
    let resp = post_request(&url, body)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyProvisionResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

pub fn decrypt_and_save_bls_key(resp: &KeyProvisionResponse, eth_sk_bytes: &[u8]) -> Result<()> {
    // hex decode the ciphertext bls secret key
    let ct_bls_sk = hex::decode(&resp.ct_bls_sk_hex)?;

    // decrypt ct_bls_sk using ephemeral eth_sk
    let bls_sk_bytes = decrypt(eth_sk_bytes, &ct_bls_sk)?;

    // recover the bls secret key
    let bls_sk = match SecretKey::from_bytes(&bls_sk_bytes) {
        Ok(sk) => sk,
        Err(e) => bail!("Couldn't recover bls_sk after decryption: {:?}", e),
    };

    let bls_sk_hex = hex::encode(bls_sk.to_bytes());

    // save the secret key
    write_key(&format!("bls_keys/generated/{}", resp.bls_pk_hex), &bls_sk_hex)?;
    println!("got bls_sk: {:?}", bls_sk);
    Ok(())
}

pub async fn bls_key_gen_provision_request() -> Result<impl warp::Reply, warp::Rejection> {
    // generate and save a new ETH pk/sk
    let (eth_sk, eth_pk_hex) = match new_eth_key() {
        Ok((sk, pk)) => (sk, hex::encode(pk.serialize())),
        Err(e) =>  {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            return Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    };

    // TODO perform real remote attestation
    let evidence = fetch_dummy_evidence();
    let req_body = KeyProvisionRequest { eth_pk_hex, evidence };

    // decrypt the returned BLS secret key and save it
    match bls_key_gen_provision_post_request(req_body).await {
        Ok(resp) => {
            match decrypt_and_save_bls_key(&resp, &eth_sk.serialize()) {
                Ok(()) => Ok(reply::with_status(reply::json(&resp), StatusCode::OK)),
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", e.to_string());
                    Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR)) 
                }
            }
        },
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


/// Makes a Reqwest POST request to the API endpoint to get a KeyImportResponse
pub async fn bls_key_import_post_request(req: KeyImportRequest) -> Result<KeyImportResponse> {
    let url = format!("http://localhost:3030/portal/v1/keystores/import");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyImportResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

/// Handles errors and prepares an http response for running `bls_key_import_post_request`
pub async fn bls_key_import_request(req: KeyImportRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match bls_key_import_post_request(req).await {
        Ok(resp) => {
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


#[cfg(test)]
mod tests {
    use ecies::encrypt;
    use crate::keys::new_bls_key;
    use crate::routes::*;
    use super::*;

    #[tokio::test]
    async fn test_btc_pricefeed_route() {
        let filter = btc_pricefeed_route();

        let res = warp::test::request()
            .path("/portal/v1/datafeed")
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);
        println!{"{:?}", res.body()};
    }

    #[tokio::test]
    async fn test_request_bls_key_gen_route() {
        let filter = request_bls_key_gen_route();

        let res = warp::test::request()
            .method("POST")
            .path("/portal/v1/keystores")
            .reply(&filter)
            .await;
        println!{"{:?}", res.body()};
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn test_request_list_bls_keys_route() {
        let filter = request_list_bls_keys_route();

        let res = warp::test::request()
            .method("GET")
            .path("/portal/v1/keystores")
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);
        println!{"{:?}", res.body()};
    }

    #[tokio::test]
    async fn test_request_bls_key_import_route() {
        let filter = request_bls_key_import_route();

        // generate ETH sk (abuse that we are working in a shared fs and this key will be saved in leader's fs)
        let leader_eth_pk = eth_key_gen().unwrap();
        let encrypting_pk_hex = hex::encode(leader_eth_pk.serialize());

        // generate a new BLS sk to import
        let bls_sk = new_bls_key().unwrap();
        let ct_bls_sk = encrypt(&leader_eth_pk.serialize(), &bls_sk.serialize()).unwrap();
        let ct_bls_sk_hex = hex::encode(ct_bls_sk);
        let bls_pk_hex = hex::encode(bls_sk.sk_to_pk().serialize());

        let req = KeyImportRequest {
            ct_bls_sk_hex,
            bls_pk_hex: bls_pk_hex.clone(),
            encrypting_pk_hex
        };
        println!("making bls key import req: {:?}", req);

        let res = warp::test::request()
            .method("POST")
            .header("accept", "application/json")
            .path("/portal/v1/keystores/import")
            .json(&req)
            .reply(&filter)
            .await;

        println!{"{:?}", res.body()};
        assert_eq!(res.status(), 200);

        let resp: KeyImportResponse = serde_json::from_slice(&res.body()).unwrap();

        assert_eq!(resp.data[0].status, "imported".to_string());
        assert_eq!(resp.data[0].message, bls_pk_hex);

    }
}