use reqwest;
use serde::Serialize;
use warp::{Filter, http::Response, http::StatusCode};

use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize};
// use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

pub async fn get_request(url: &String) -> Result<reqwest::Response> {
    reqwest::get(url).await.with_context(|| "Failed GET reqwest")
}

pub async fn post_request_no_body(url: &String) -> Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client.post(url).send().await.with_context(|| "Failed POST reqwest with no body")
}

pub async fn post_request<T: Serialize>(url: &String, body: T) -> Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client.post(url).json(&body).send().await.with_context(|| "Failed POST reqwest with body")
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

/// makes a GET reqwest to coin
pub async fn coindesk_usd_feed(url: String) -> Result<f64> {
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<CoinDeskResp>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);

    let rate = resp.bpi["USD"].rate_float;
    Ok(rate)
}

pub async fn get_btc_price_feed() -> Result<impl warp::Reply, warp::Rejection> {
    let url = format!("https://api.coindesk.com/v1/bpi/currentprice.json");
    match coindesk_usd_feed(url.clone()).await {
        Ok((price)) => {
            let mut resp = HashMap::new();
            resp.insert("price", price);
            Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

fn get_data(url: String) -> String {
    String::from("Here is some data")
}

fn process_resp(resp: String) -> String {
    String::from("Here is the processed string")
}