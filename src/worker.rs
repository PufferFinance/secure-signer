#[macro_use]
extern crate anyhow;

mod keys;
mod datafeed;
mod attest;
mod worker_api;

use anyhow::{Result, Context, bail};
use datafeed::{get_btc_price_feed, get_request, post_request_no_body};
use keys::ListKeysResponse;

use warp::{Filter, http::Response};


pub async fn list_keys_request() -> Result<()> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<ListKeysResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(())
}

pub async fn key_gen_request() -> Result<()> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = post_request_no_body(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<keys::KeyGenResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(())
}

use worker_api::*;

#[tokio::main]
async fn main() {
    // list_keys_request().await?;
    // key_gen_request()?;
    let port = 3030;
    println!("Starting worker enclave HTTP server");
    let route = worker_api::btc_pricefeed_route();
    warp::serve(route).run(([127, 0, 0, 1], port)).await;
}