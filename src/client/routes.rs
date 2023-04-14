use puffersecuresigner::{api::{KeyGenResponse, getter_routes::ListKeysResponse, helpers::SignatureResponse, KeyImportResponse}, eth2::eth_types::DepositResponse};
use anyhow::{bail, Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned};
use std::path::PathBuf;
pub enum RouteType {
    Upcheck,
    BlsSign,
    BlsKeyImport,
    BlsKeygen,
    EthKeygen,
    ListEthKeys,
    ListBlsKeys,
    Deposit,
}

impl RouteType {
    pub fn endpoint(&self) -> &str {
        match &self {
            RouteType::Upcheck => "/upcheck",
            RouteType::BlsSign => "/api/v1/eth2/sign",
            RouteType::BlsKeygen => "/eth/v1/keygen/bls",
            RouteType::BlsKeyImport => "/eth/v1/keystores",
            RouteType::ListBlsKeys => "/eth/v1/keystores",
            RouteType::EthKeygen => "/eth/v1/keygen/secp256k1",
            RouteType::ListEthKeys => "/eth/v1/keygen/secp256k1",
            RouteType::Deposit => "/api/v1/eth2/deposit",
        }
    }
}

pub fn build_req_url(port: u16, route: RouteType, pk_hex: Option<&str>) -> Result<String> {
    let uri = format!("http://localhost:{port}");
    let mut components = vec![route.endpoint()];
    if pk_hex.is_some() {
        components.push(pk_hex.unwrap());
    }
    let path: PathBuf = components.iter().collect();
    if let Some(p) = path.to_str() {
        Ok(uri + &p.to_string())
    } else {
        bail!("Failed to build url: {:?}", path)
    }
}

pub async fn get(url: &str) -> Result<Response, reqwest::Error> {
    let client = Client::new();
    client.get(url).send().await
}

pub async fn get_json<T: DeserializeOwned> (url: &str) -> Result<(StatusCode, Result<T>)> {
    let client = Client::new();
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let json_resp: Result<T> = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to T"));
            Ok((status, json_resp))
        },
        Err(e) => bail!("get_json failed: {:?}", e),
    }
}

pub async fn post<T: DeserializeOwned> (url: &str, json: Option<&String>) -> Result<(StatusCode, Result<T>)> {
    let client = Client::new();
    let resp = match json {
        Some(json) => {
            client
                .post(&url.to_string())
                .header("Content-Type", "application/json")
                .body(json.clone())
                .send()
                .await
        }
        None => client.post(&url.to_string()).send().await,
    };

    match resp {
        Ok(resp) => {
            let status = resp.status();
            let json_resp: Result<T> = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to T"));
            Ok((status, json_resp))
        },
        Err(e) => bail!("Post request failed: {:?}", e),
    }

}

pub async fn is_alive(port: u16) -> Result<()> {
    let url = build_req_url(port, RouteType::Upcheck, None)?;
    match get(&url).await {
        Ok(resp) => {
            if resp.status() == 200 {
                Ok(())
            } else {
                bail!("Upcheck did not receive 200");
            }
        }
        Err(e) => bail!("Upcheck failure: {:?}", e),
    }
}

pub async fn bls_sign(port: u16, json: &String, pk_hex: &String) -> Result<SignatureResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::BlsSign, Some(pk_hex))?;
    let (status, resp) = post::<SignatureResponse>(&url, Some(json)).await?;
    if status != 200 {
        bail!("bls_sign_route received {status} response")
    }
    resp
}

pub async fn deposit(port: u16, json: &String) -> Result<DepositResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::Deposit, None)?;
    let (status, resp) = post::<DepositResponse>(&url, Some(json)).await?;
    if status != 200 {
        bail!("deposit received {status} response")
    }
    resp
}

pub async fn bls_key_import(port: u16, json: &String) -> Result<KeyImportResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::BlsKeyImport, None)?;
    let (status, resp) = post::<KeyImportResponse>(&url, Some(json)).await?;
    if status != 200 {
        bail!("bls_key_import_route received {status} response")
    }
    resp
}

pub async fn bls_keygen(port: u16) -> Result<KeyGenResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::BlsKeygen, None)?;
    let (status, resp) = post::<KeyGenResponse>(&url, None).await?;
    if status != 200 {
        bail!("bls_keygen_route received {status} response")
    }
    resp
}

pub async fn eth_keygen(port: u16) -> Result<KeyGenResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::EthKeygen, None)?;
    let (status, resp) = post::<KeyGenResponse>(&url, None).await?;
    if status != 200 {
        bail!("eth_keygen_route received {status} response")
    }
    resp
}

pub async fn list_eth_keys(port: u16) -> Result<ListKeysResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::ListEthKeys, None)?;
    let (status, resp) = get_json::<ListKeysResponse>(&url).await?;
    if status != 200 {
        bail!("list_eth_keys_route received {status} response")
    }
    resp
}

pub async fn list_bls_keys(port: u16) -> Result<ListKeysResponse> {
    is_alive(port).await?;
    let url = build_req_url(port, RouteType::ListBlsKeys, None)?;
    let (status, resp) = get_json::<ListKeysResponse>(&url).await?;
    if status != 200 {
        bail!("list_bls_keys_route received {status} response")
    }
    resp
}