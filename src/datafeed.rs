use crate::errors::*;

use reqwest;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn get_request(url: String) -> Result<reqwest::blocking::Response> {
    Ok(reqwest::blocking::get(url)?)
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
    let resp = get_request(url)
        .chain_err(|| "failed GET request")?
        .json::<CoinDeskResp>()
        .chain_err(|| "could not parse json response")?;
    println!("{:#?}", resp);

    let rate = resp.bpi["USD"].rate_float;
    Ok(rate)
}

pub fn get_btc_price_feed() -> Result<()> {
    let url = format!("https://api.coindesk.com/v1/bpi/currentprice.json");
    let rate = coindesk_usd_feed(url).chain_err(|| "could not fetch rate")?;
    println!("Got rate: {}", rate);
    Ok(())
}


























fn get_data(url: String) -> String {
    String::from("Here is some data")
}

fn process_resp(resp: String) -> String {
    String::from("Here is the processed string")
}