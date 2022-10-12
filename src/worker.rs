#[macro_use]
extern crate anyhow;

use anyhow::{Result, Context, bail};
mod keys;
mod datafeed;
mod attest;

use datafeed::{get_btc_price_feed, get_request, post_request_no_body};
use keys::ListKeysResponse;

use warp::{Filter, http::Response};


fn list_keys_request() -> Result<()> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = get_request(&url)
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<ListKeysResponse>()
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(())
}

fn key_gen_request() -> Result<()> {
    let url = format!("http://localhost:3030/portal/v1/keystores");
    let resp = post_request_no_body(&url)
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<keys::KeyGenResponse>()
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(())
}

fn main() -> Result<()> {
    get_btc_price_feed()?;
    // list_keys_request();
    // key_gen_request()?;
    Ok(())
}