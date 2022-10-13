use anyhow::{Result, Context, bail};
use warp::{reply, Filter, http::Response, http::StatusCode};
use crate::datafeed::{get_btc_price_feed, get_request, post_request_no_body};
use crate::leader_api::{ListKeysResponse, KeyGenResponse};

use std::collections::HashMap;


/// Makes a Reqwest GET request to the API endpoint to get a ListKeysResponse
pub async fn list_bls_keys_get_request() -> Result<ListKeysResponse> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<ListKeysResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

/// Handles errors and prepares an http response for running `list_bls_keys_get_request`
pub async fn list_bls_keys_request() -> Result<impl warp::Reply, warp::Rejection> {
    match list_bls_keys_get_request().await {
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

/// Asks the server Sample client route for getting a specific datafeed
pub fn request_list_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_bls_keys_request)
}

/// 
pub async fn bls_key_gen_get_request() -> Result<KeyGenResponse> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = post_request_no_body(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<KeyGenResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

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

/// Asks the server Sample client route for getting a specific datafeed
pub fn request_bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(bls_key_gen_request)
}

/// Sample client route for getting a specific datafeed
pub fn btc_pricefeed_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("datafeed"))
        .and_then(get_btc_price_feed)
}

#[cfg(test)]
mod tests {
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
}