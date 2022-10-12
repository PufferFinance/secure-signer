use reqwest;

use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn get_request(url: &String) -> Result<reqwest::blocking::Response> {
    reqwest::blocking::get(url).with_context(|| "Failed GET reqwest")
}

pub fn post_request_no_body(url: &String) -> Result<reqwest::blocking::Response> {
    let client = reqwest::blocking::Client::new();
    client.post(url).send().with_context(|| "Failed POST reqwest with no body")
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct TimeFields {
    pub updated: String,
    pub updatedISO: String,
    pub updateduk: String,
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct CoinDeskResp {
    pub time: TimeFields,
    pub disclaimer: String,
    pub chartName: String,
    pub bpi: HashMap<String, PriceInfo>,
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct PriceInfo {
    pub code: String,
    pub symbol: String,
    pub rate: String,
    pub description: String,
    pub rate_float: f64,
}

pub fn coindesk_usd_feed(url: String) -> Result<f64> {
    let resp = get_request(&url)
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<CoinDeskResp>()
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);

    let rate = resp.bpi["USD"].rate_float;
    Ok(rate)
}

pub fn get_btc_price_feed() -> Result<()> {
    let url = format!("https://api.coindesk.com/v1/bpi/currentprice.json");
    let rate = coindesk_usd_feed(url.clone()).with_context(|| format!("could not fetch rate from url: {}", url))?;
    println!("Got rate: {}", rate);
    Ok(())
}

fn get_data(url: String) -> String {
    String::from("Here is some data")
}

fn process_resp(resp: String) -> String {
    String::from("Here is the processed string")
}