extern crate anyhow;

mod eth_signing;
mod eth_types;
mod keys;
mod remote_attestation;
mod route_handlers;
mod routes;
mod slash_protection;

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
    Ok(resp)
}

async fn import_bls_key(
    host: String,
    keystore_str: String,
    password: String,
    ss_eth_pk_hex: String,
    slash_protection_path: Option<String>,
) -> Result<KeyImportResponse> {

    // ECDH envelope encrypt keystore password with Secure-Signer's SECP256K1 public key
    let ss_eth_pk_hex_stripped: String = ss_eth_pk_hex
        .strip_prefix("0x")
        .unwrap_or(&ss_eth_pk_hex)
        .into();
    let ss_eth_pk_bytes = hex::decode(&ss_eth_pk_hex_stripped)?;
    let ct_password_bytes = encrypt(&ss_eth_pk_bytes, &password.as_bytes())?;
    let ct_password_hex = "0x".to_string() + &hex::encode(ct_password_bytes);

    let slash_protection = match slash_protection_path {
        None => None,
        Some(dir) => {
            let s: String = fs::read_to_string(dir).expect("couldn't read slash protection file");
            Some(s)
        }
    };

    // Bundle together
    let req = KeyImportRequest {
        keystore: keystore_str,
        ct_password_hex: ct_password_hex,
        encrypting_pk_hex: ss_eth_pk_hex,
        slashing_protection: slash_protection,
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

    Ok(pk)
}

fn eth_addr_to_credentials(addr: String) -> Result<String> {
    let addr: String = addr.strip_prefix("0x").unwrap_or(&addr).into();
    if addr.len() != 40 {
        bail!("Invalid length ETH address")
    }
    let withdrawal_credentials = format!("0x010000000000000000000000{addr}");
    Ok(withdrawal_credentials)
}

/// Makes a Reqwest POST request to the /eth/v1/keystores API endpoint to get a KeyImportResponse
pub async fn deposit_post_request(
    pk_hex: String,
    req: String,
    host: String,
) -> Result<DepositResponse> {
    let req: serde_json::Value = serde_json::from_str(&req).unwrap();
    let url = format!("{host}/api/v1/eth2/sign/{pk_hex}");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<DepositResponse>()
        .await
        .with_context(|| format!("could not parse json response from : {}", url))?;
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

pub fn deposit_data_payload(d: DepositResponse, config: NetworkConfig) -> String {
    let pubkey = d.pubkey;
    let withdrawal_credentials = d.withdrawal_credentials;
    let amount = d.amount;
    let signature = d.signature;
    let deposit_message_root = d.deposit_message_root;
    let deposit_data_root = d.deposit_data_root;
    let network_name = config.network_name;
    let fork_version = config.fork_version;
    let deposit_cli_version = config.deposit_cli_version;

    // Build deposit JSON that works with https://goerli.launchpad.ethereum.org/en/upload-deposit-data
    format!(r#"
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
    )

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
    assert_eq!(pk_hex, resp.pub_key);
    let evidence = resp.evidence;

    // Save the evidence
    write_evidence_to_file(&evidence, filename);

    // Verify rpt signed by valid intel cert  
    evidence.verify_intel_signing_certificate()?;

    // Extract pk from report body
    let got_pk_hex = if bls {
        let got_pk = evidence.get_bls_pk()?;
        bls_pk_to_hex(&got_pk)
    } else {
        let got_pk = evidence.get_eth_pk()?;
        eth_pk_to_hex(&got_pk)
    };
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    if pk_hex != got_pk_hex { bail!("report has mismatched public key") }

    // extract mrencalve from report body
    let got_mre = evidence.get_mrenclave()?;
    let exp_mre: String = mrenclave.strip_prefix("0x").unwrap_or(&mrenclave).into();
    if exp_mre != got_mre { 
        println!("received MRENCLAVE: {got_mre}");
        bail!("report has mismatched MRENCLAVE") 
    }
    Ok(())

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub network_name: String,
    pub fork_version: String,
    pub deposit_cli_version: String,
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

    /// Requests Secure-Signer to generate BLS key perform remote attestation [requires --mrenclave]
    #[arg(short, long)]
    bls_keygen: bool,

    /// Requests Secure-Signer to list all of its keys 
    #[arg(short, long)]
    list: bool,

    /// The path to a BLS keystore [requires --password, --mrenclave]
    #[arg(long)]
    import: Option<String>,

    /// The password to the keystore
    #[arg(long)]
    password: Option<String>,

    /// The path to EIP-3076 .JSON
    #[arg(long)]
    slash_protection_path: Option<String>,

    /// Request Secure-Signer to generate a DepositData [requires validator-pk-hex, --withdrawal-addr]
    #[arg(short, long)]
    deposit: bool,

    /// The validator public key in hex
    #[arg(short, long)]
    validator_pk_hex: Option<String>,

    /// The ETH address for withdrawals
    #[arg(short, long)]
    execution_addr: Option<String>,

    /// The expected MRENCLAVE value
    #[arg(long)]
    mrenclave: Option<String>,

    /// The path to the JSON network config file
    #[arg(short, long, default_value = "./conf/network_config.json")]
    config: String,

    /// Locally generates a BLS keystore with the supplied name [requires --password]
    #[arg(short, long)]
    new_local_bls: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let dir = Path::new(&args.outdir);
    let dir_str = &dir.to_str().unwrap();
    fs::create_dir_all(dir);

    let config = NetworkConfig::new(args.config); 

    let port = args.port;
    println!("- Connecting to Secure-Signer on port {}", port);
    let host = format!("http://localhost:{port}");

    // run /upcheck to see if SS online
    run_upcheck(host.clone()).await.expect("Couldn't reach SS is it online?");

    // ------- for listing all keys in SS -------
    if args.list {
        // generated bls
        println!("Generated BLS keys:");
        list_keys(host.clone(), true, false).await;

        // imported bls
        println!("Imported BLS keys:");
        list_keys(host.clone(), true, true).await;

        // generated secp256k1
        println!("Generated SECP256K1 keys:");
        list_keys(host.clone(), false, false).await;

        return
    }

    // ------- for generating BLS key in SS -------
    if args.bls_keygen {
        // request Secure-Signer generate BLS key
        let ss_bls_pk_hex = get_new_bls_pk(host.clone()).await.expect("SS failed to gen new BLS key");
        let mrenclave = args.mrenclave.expect("--mrenclave missing");
        println!("- Secure-Signer generated BLS public key: {ss_bls_pk_hex}");

        // request Secure-Signer to perform Remote Attestation with their BLS key
        #[cfg(target_os = "linux")]
        match verify_remote_attestation(ss_bls_pk_hex.clone(), host.clone(), mrenclave, true, &format!("{dir_str}/bls-ra-evidence.json")).await {
            Ok(()) => println!("- Secure-Signer BLS public key passed remote attestation"),
            Err(e) => println!("- WARNING, failed to verify Remote Attestation evidence! {:?}", e)
        };

        // list all generated keys
        list_keys(host.clone(), true, false).await;
        return 
    }

    // ------- for importing BLS key into SS -------
    if args.import.is_some() {
        // Load BLS keystore
        let keystore_pw = args.password.expect("keystore password expected");
        let keystore_path = args.import.expect("bad keystore path");
        let keystore_str: String = fs::read_to_string(keystore_path).expect("couldn't read keystore");
        let mrenclave = args.mrenclave.expect("--mrenclave missing");

        // request a new ETH key from Secure-Signer
        let ss_eth_pk_hex = get_new_eth_pk(host.clone()).await.expect("SS failed to gen new ETH key");
        println!("- Secure-Signer generated ETH public key: {ss_eth_pk_hex}");

        // request Secure-Signer to perform Remote Attestation with their ETH key
        #[cfg(target_os = "linux")]
        match verify_remote_attestation(ss_eth_pk_hex.clone(), host.clone(), mrenclave.clone(), false, &format!("{dir_str}/eth-ra-evidence.json")).await {
            Ok(()) => println!("- Secure-Signer ETH public key passed remote attestation"),
            Err(e) => {
                println!("- ERROR, failed to verify Remote Attestation evidence, aborting BLS key import! {:?}", e);
                return
            }
        };

        // securely import BLS private key into Secure-Signer
        let returned_bls_pk_resp = import_bls_key(host.clone(), keystore_str, keystore_pw, ss_eth_pk_hex, args.slash_protection_path)
            .await
            .unwrap();
        let returned_bls_pk_raw = returned_bls_pk_resp.data[0].message.clone();
        let returned_bls_pk = returned_bls_pk_raw.strip_prefix("0x").unwrap_or(&returned_bls_pk_raw).to_string();
        println!("- Securely transfered validator key to Secure-Signer: {:?}", returned_bls_pk);

        // request Secure-Signer to perform Remote Attestation with their BLS key
        #[cfg(target_os = "linux")]
        verify_remote_attestation(returned_bls_pk, host.clone(), mrenclave.clone(), true, &format!("{dir_str}/bls-ra-evidence.json")).await.unwrap();
        println!("- Imported BLS public key passed remote attestation");

        // List all imported keys
        let url = format!("{host}/eth/v1/keystores");
        list_keys(host.clone(), true, true).await;
        return 
    }

    // ------- for creating DepositData -------
    if args.deposit {
        let validator_pk_hex = args.validator_pk_hex.expect("Validator public key (hex) required for DepositData");
        let withdrawal_addr = args.execution_addr.expect("ETH address (hex) required for withdrawal credentials");

        let withdrawal_credentials = match eth_addr_to_credentials(withdrawal_addr) {
            Ok(w) => {
                println!("Using withdrawal_credentials: {w}");
                w
            },
            Err(e) => {
                println!("- ERROR, failed to create withdrawal credentials! {:?}", e);
                return
            }   
        };

        // Send DEPOSIT message
        let deposit_msg =
            build_deposit_msg(&validator_pk_hex, &withdrawal_credentials, &config.fork_version).unwrap();

        // Get DepositResponse from SS
        let deposit_resp = get_deposit_signature(validator_pk_hex.clone(), deposit_msg, &host)
            .await
            .unwrap();

        // Convert to a payload for the ETH launchpad
        let dd = deposit_data_payload(deposit_resp, config);
        
        // Write the deposit data to the out dir
        let p = dir.join("deposit_data.json");
        println!("Writing DepositData to {:?}", p);
        fs::write(p, dd).unwrap();
        return 
    }

    if args.new_local_bls.is_some() {
        let pw = args.password.expect("Password required to save new BLS keystore");
        let name = args.new_local_bls.expect("Keystore filename required");

        match new_bls_keystore(dir, Some(&name), &pw) {
            Ok(pk) => println!("Saved keystore with pk: 0x{}", hex::encode(&pk.compress())),
            Err(e) => println!("ERROR: {:?}", e)
        };
        return
    }

    println!("No commands ran, use `--help` flag for usage")

}
