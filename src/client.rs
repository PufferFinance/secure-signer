extern crate anyhow;

mod eth_signing;
mod eth_types;
mod keys;
mod remote_attestation;
mod route_handlers;
mod routes;

use eth_types::DepositResponse;
use route_handlers::{SecureSignerSig, KeyGenResponse, KeyImportRequest, KeyImportResponse, RemoteAttestationResponse, ListKeysResponse};
use keys::{eth_pk_to_hex, bls_pk_to_hex};
use remote_attestation::{AttestationEvidence};

use anyhow::{bail, Context, Result};
use blst::min_pk::{PublicKey, SecretKey};
use clap::Parser;
use ecies::{decrypt, encrypt};
use reqwest;
use serde::{Serialize, Deserialize};
use serde_json;
use std::fs::File;
use std::io::prelude::*;

use eth_keystore::{decrypt_key};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};


pub async fn post_request<T: Serialize>(url: &String, body: T) -> Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| "Failed POST reqwest with body")
}

pub async fn get_request(url: &String) -> Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client
        .get(url)
        .send()
        .await
        .with_context(|| "Failed GET reqwest with body")
}

async fn run_upcheck(
    host: String,
) -> Result<()> {
    let url = format!("{host}/upcheck");
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        bail!("{url} did not return 200, is Secure-Signer running?")
    }
}

/// Makes a Reqwest POST request to the /eth/v1/keystores API endpoint to get a KeyImportResponse
pub async fn bls_key_import_post_request(
    req: KeyImportRequest,
    host: String,
) -> Result<KeyImportResponse> {
    let url = format!("{host}/eth/v1/keystores");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyImportResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    // println!("{:#?}", resp);
    Ok(resp)
}

async fn import_bls_key(
    host: String,
    client_bls_sk_hex: String,
    ss_eth_pk_hex: String,
) -> Result<KeyImportResponse> {
    // Compute bls pk
    let client_bls_sk = keys::bls_sk_from_hex(client_bls_sk_hex)?;
    let client_bls_pk_hex: String =
        "0x".to_string() + &hex::encode(client_bls_sk.sk_to_pk().compress());

    // ECDH envelope encrypt client BLS key with Secure-Signer's SECP256K1 public key
    let ss_eth_pk_hex_stripped: String = ss_eth_pk_hex
        .strip_prefix("0x")
        .unwrap_or(&ss_eth_pk_hex)
        .into();
    let ss_eth_pk_bytes = hex::decode(&ss_eth_pk_hex_stripped)?;
    let client_ct_bls_sk_bytes = encrypt(&ss_eth_pk_bytes, &client_bls_sk.serialize())?;
    let client_ct_bls_sk_hex = "0x".to_string() + &hex::encode(client_ct_bls_sk_bytes);

    // Bundle together
    let req = KeyImportRequest {
        ct_bls_sk_hex: client_ct_bls_sk_hex,
        bls_pk_hex: client_bls_pk_hex,
        encrypting_pk_hex: ss_eth_pk_hex,
    };

    // println!("{:#?}", req);
    let resp = bls_key_import_post_request(req, host).await?;
    Ok(resp)
}

async fn list_keys(
    host: String,
    bls: bool,
    imported: bool,
) -> Result<()> {
    let url = match bls {
        true => {
            match imported {
                true => format!("{host}/eth/v1/keystores"),
                false => format!("{host}/eth/v1/keygen/bls"),
            }
        },
        false => format!("{host}/eth/v1/keygen/secp256k1"),
    };
    let resp = get_request(&url)
        .await
        .with_context(|| format!("failed GET request to URL: {}", url))?
        .json::<ListKeysResponse>()
        .await
        .with_context(|| format!("could not parse json response from : {}", url))?;
    println!("{:#?}", resp);
    Ok(())
}

/// Makes a Reqwest POST request to the /eth/v1/keygen/secp256k1 or /eth/v1/keygen/secp256k1 API endpoint (depends on bls: bool argument) to get a KeyGenResponse
pub async fn keygen_post_request(host: String, bls: bool) -> Result<KeyGenResponse> {
    let url = match bls {
        true => format!("{host}/eth/v1/keygen/bls"),
        false => format!("{host}/eth/v1/keygen/secp256k1"),
    };
    let resp = post_request(&url, {})
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyGenResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    // println!("{:#?}", resp);
    Ok(resp)
}

async fn get_new_eth_pk(host: String) -> Result<String> {
    let resp = keygen_post_request(host, false).await?;
    Ok(resp.pk_hex)
}

async fn get_new_bls_pk(host: String) -> Result<String> {
    let resp = keygen_post_request(host, true).await?;
    Ok(resp.pk_hex)
}

fn new_bls_keystore(dir: &Path, name: Option<&str>, password: &str) -> Result<PublicKey> {
    let mut rng = rand::thread_rng();
    let (private_key, fname) = eth_keystore::new(&dir, &mut rng, password, name)?;
    
    // get the public key
    let pk = match keys::bls_sk_from_hex(hex::encode(&private_key)) {
        Ok(sk) => sk.sk_to_pk(),
        Err(e) => {
            // sometimes generates bad encoded bls key, keep trying
            if name.is_some() {
                fs::remove_file(dir.join(&name.unwrap()))?;
            } else {
                fs::remove_file(dir.join(&fname))?;
            }
            new_bls_keystore(dir, name, password)?
        }
    };

    // println!(
    //     "DEBUG new keystore: public key: {:?}, private_key: {:?}",
    //     hex::encode(pk.compress()),
    //     hex::encode(private_key)
    // );
    Ok(pk)
}

fn new_withdrawal_key(dir: &Path, password: &str) -> Result<(String, String)> {
    let pk = new_bls_keystore(dir, Some("withdrawal-keystore.json"), password)?;
    let withdrawal_bls_pk_hex = "0x".to_string() + &hex::encode(pk.compress());
    let withdrawal_credentials = "0x".to_string() + &hex::encode(&keys::keccak(&pk.compress())?);
    Ok((withdrawal_bls_pk_hex, withdrawal_credentials))
}

/// Makes a Reqwest POST request to the /eth/v1/keystores API endpoint to get a KeyImportResponse
pub async fn deposit_post_request(
    pk_hex: String,
    req: String,
    host: String,
) -> Result<DepositResponse> {
    let req: serde_json::Value = serde_json::from_str(&req).unwrap();
    println!("{:#?}", req);
    let url = format!("{host}/api/v1/eth2/sign/{pk_hex}");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<DepositResponse>()
        .await
        .with_context(|| format!("could not parse json response from : {}", url))?;
    // println!("{:#?}", resp);
    Ok(resp)
}

fn build_deposit_msg(
    validator_pk_hex: &str,
    withdrawal_credentials: &str,
    fork_version: &str,
) -> Result<String> {
    let amount: u64 = 32000000000;

    let req = format!(
        r#"
    {{
        "type": "DEPOSIT",  
        "deposit": {{
            "pubkey": "{validator_pk_hex}",
            "withdrawal_credentials": "{withdrawal_credentials}",
            "amount":"{amount}"
        }},
        "genesis_fork_version": "{fork_version}"
    }}"#
    );
    Ok(req)
}

pub async fn get_deposit_signature(
    pk_hex: String,
    req: String,
    host: &str,
) -> Result<DepositResponse> {
    deposit_post_request(pk_hex, req, host.to_string()).await
}

/// Makes a Reqwest POST request to the /eth/v1/remote-attestation/0xdeadbeef... API endpoint to get a RemoteAttestationResponse
pub async fn remote_attestation_post_request(
    pk_hex: String,
    host: String,
) -> Result<RemoteAttestationResponse> {
    let url = format!("{host}/eth/v1/remote-attestation/{pk_hex}");
    let resp = post_request(&url, {})
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<RemoteAttestationResponse>()
        .await
        .with_context(|| format!("could not parse json response from : {}", url))?;
    // println!("{:#?}", resp);
    Ok(resp)
}

fn write_evidence_to_file(evidence: &AttestationEvidence, filename: &str) -> Result<()> {
    let json = serde_json::to_string(evidence).with_context(|| "failed to convert evidence to json string")?;
    fs::write(filename, json).with_context(|| "failed to write evidence to file")
}

pub async fn verify_remote_attestation(
    pk_hex: String,
    host: String,
    mrenclave: String,
    bls: bool,
    filename: &str,
) -> Result<()> {
    let resp: RemoteAttestationResponse = remote_attestation_post_request(pk_hex.clone(), host).await?;
    println!("{:#?}", resp);
    assert_eq!(pk_hex, resp.pub_key);
    let evidence = resp.evidence;
    // verify rpt signed by valid intel cert  
    evidence.verify_intel_signing_certificate()?;

    // extract pk from report body
    let got_pk_hex = if bls {
        let got_pk = evidence.get_bls_pk()?;
        bls_pk_to_hex(&got_pk)
    } else {
        let got_pk = evidence.get_eth_pk()?;
        eth_pk_to_hex(&got_pk)
    };
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    assert_eq!(pk_hex, got_pk_hex);

    // extract mrencalve from report body
    let got_mre = evidence.get_mrenclave()?;
    println!("got MRENCLAVE: {got_mre}");
    // assert_eq!(mrenclave, ); // todo

    write_evidence_to_file(&evidence, filename)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetworkConfig {
    network_name: String,
    fork_version: String,
    deposit_cli_version: String,
}

impl NetworkConfig {
    fn new(path: String) -> Self {
        let file = File::open(path).expect("bad config path");
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).expect("bad deserialize config")
    }
}

/// Secure-Signer Client Interface
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// The port that Secure-Signer is exposing
   #[arg(short, long, default_value_t = 9001)]
   port: u16,

   /// The path to the directory to save Secure-Signer outputs
   #[arg(short, long, default_value = "./ss_out")]
   outdir: String,

   /// Requests Secure-Signer to generate BLS key perform remote attestation
   #[arg(short, long)]
   bls_keygen: bool,

   /// The path to a BLS keystore
   #[arg(long)]
   import: Option<String>,

   /// The password to the keystore
   #[arg(long)]
   password: Option<String>,

   /// Request Secure-Signer to generate a DepositData
   #[arg(short, long)]
   deposit: bool,

   /// The validator public key in hex
   #[arg(short, long)]
   validator_pk_hex: Option<String>,

   /// The expected MRENCLAVE value
   #[arg(long)]
   mrenclave: Option<String>,

    /// The path to the JSON network config file
    #[arg(short, long, default_value = "network_config.json")]
    config: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let dir = Path::new(&args.outdir);
    let dir_str = &dir.to_str().unwrap();

    let config = NetworkConfig::new(args.config); 

    let port = args.port;
    println!("- Connecting to Secure-Signer on port {}", port);
    let host = format!("http://localhost:{port}");

    // run /upcheck to see if SS online
    run_upcheck(host.clone()).await.unwrap();

    // ------- for generating BLS key in SS -------
    if args.bls_keygen {
        // request Secure-Signer generate BLS key
        let ss_bls_pk_hex = get_new_bls_pk(host.clone()).await.expect("SS failed to gen new BLS key");
        println!("- Secure-Signer generated BLS public key: {ss_bls_pk_hex}");

        // request Secure-Signer to perform Remote Attestation with their ETH key
        let mrenclave = "".into(); // TODO from CLI
        verify_remote_attestation(ss_bls_pk_hex.clone(), host.clone(), mrenclave, true, &format!("{dir_str}/bls-ra-evidence.json")).await.unwrap();
        println!("- Secure-Signer BLS public key passed remote attestation");

        let url = format!("{host}/eth/v1/keystores");
        list_keys(host.clone(), true, false).await;
        return 
    }

    // ------- for importing BLS key into SS -------
    if args.import.is_some() && args.password.is_some() {
        // Load BLS keystore
        let (client_bls_sk_hex, client_bls_pk_hex) =
            keys::load_keystore(args.import.as_ref().unwrap(), args.password.as_ref().unwrap()).expect("failed to read keystore");

        // request a new ETH key from Secure-Signer
        let ss_eth_pk_hex = get_new_eth_pk(host.clone()).await.expect("SS failed to gen new ETH key");
        println!("- Secure-Signer generated ETH public key: {ss_eth_pk_hex}");

        // request Secure-Signer to perform Remote Attestation with their ETH key
        let mrenclave = "".into(); // TODO from CLI
        verify_remote_attestation(ss_eth_pk_hex.clone(), host.clone(), mrenclave, false, &format!("{dir_str}/eth-ra-evidence.json")).await.unwrap();
        println!("- Secure-Signer ETH public key passed remote attestation");

        // securely import BLS private key into Secure-Signer
        let returned_bls_pk_resp = import_bls_key(host.clone(), client_bls_sk_hex, ss_eth_pk_hex)
            .await
            .unwrap();
        let returned_bls_pk_raw = returned_bls_pk_resp.data[0].message.clone();
        let returned_bls_pk = returned_bls_pk_raw.strip_prefix("0x").unwrap_or(&returned_bls_pk_raw).into();
        println!("- Securely transfered validator key to Secure-Signer: {:?}", returned_bls_pk);

        let url = format!("{host}/eth/v1/keystores");
        list_keys(host.clone(), true, true).await;

        let mrenclave = "".into(); // TODO from CLI
        verify_remote_attestation(returned_bls_pk, host.clone(), mrenclave, true, &format!("{dir_str}/bls-ra-evidence.json")).await.unwrap();
        println!("- Imported BLS public key passed remote attestation");
        return 
    }

    // ------- for creating DepositData -------
    if args.deposit {
        let pw = args.password.expect("Password required to save withdrawal keystore");
        let validator_pk_hex = args.validator_pk_hex.expect("Validator public key (hex) required for DepositData");

        // Create withdrawal credentials
        let (withdrawal_pk_hex, withdrawal_credentials) =
            new_withdrawal_key(dir, &pw).unwrap();

        println!(
            "Created withdrawal key {:?} with credentials {:?}",
            withdrawal_pk_hex, withdrawal_credentials
        );

        // Send DEPOSIT message
        let fork_version = &config.fork_version; 
        let deposit_msg =
            build_deposit_msg(&validator_pk_hex, &withdrawal_credentials, fork_version).unwrap();
        // println!("{:?}", deposit_msg);
        let deposit_resp = get_deposit_signature(validator_pk_hex.clone(), deposit_msg, &host)
            .await
            .unwrap();

        let pubkey = deposit_resp.pubkey;
        let withdrawal_credentials = deposit_resp.withdrawal_credentials;
        let amount = deposit_resp.amount;
        let signature = deposit_resp.signature;
        let deposit_message_root = deposit_resp.deposit_message_root;
        let deposit_data_root = deposit_resp.deposit_data_root;
        let network_name = config.network_name;
        let deposit_cli_version = config.deposit_cli_version;

        // Build deposit JSON that works with https://goerli.launchpad.ethereum.org/en/upload-deposit-data
        let dd = format!(
            r#"
        [{{
            "pubkey": "{pubkey}",
            "withdrawal_credentials": "{withdrawal_credentials}",
            "amount": {amount},
            "signature": "{signature}",
            "deposit_message_root": "{deposit_message_root}",
            "deposit_data_root": "{deposit_data_root}",
            "fork_version": "{fork_version}",
            "network_name": "{network_name}",
            "deposit_cli_version": "{deposit_cli_version}"
        }}]"#
        );
        
        let p = dir.join("deposit_data.json");
        println!("Writing DepositData to {:?}", p);
        fs::write(p, dd).unwrap();

        return 
    }

    println!("No commands were ran, run `--help` flag for usage")

}
