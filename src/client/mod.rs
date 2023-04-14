mod routes;
mod bls_import;
mod deposit;
mod withdraw;

use serde::{Serialize, Deserialize};
use clap::Parser;
use anyhow::{bail, Result};

use std::{path::{Path, PathBuf}, fs::{File, self}, io::BufReader};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub network_name: String,
    pub fork_version: String,
    pub deposit_cli_version: String,
}

impl NetworkConfig {
    fn new(path: &String) -> Self {
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

    /// Requests Secure-Signer to import a keystore [requires --mrenclave, --keystore-path, --password-path]
    #[arg(short, long)]
    import: bool,

    /// The password to the keystore
    #[arg(long)]
    keystore_path: Option<PathBuf>,

    /// The password to the keystore
    #[arg(long)]
    password_path: Option<PathBuf>,

    /// The path to EIP-3076 .JSON to import with the keystore
    #[arg(long)]
    slash_protection_path: Option<PathBuf>,

    /// Request Secure-Signer to generate a DepositData [requires validator-pk-hex, --execution-addr]
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
}

impl Args {
    pub fn init_out_dir() {
        let args = Args::parse();
        let dir = Path::new(&args.outdir);
        if let Some(dir_str) = &dir.to_str() {
            fs::create_dir_all(dir);
        } else {
            panic!("Failed to create {:?}", dir);
        }
    }

    pub fn config() -> NetworkConfig {
        NetworkConfig::new(&Args::parse().config)
    }
    
    pub fn port() -> u16 {
        Args::parse().port
    }

    pub fn do_keygen() -> bool {
        Args::parse().bls_keygen
    }

    pub fn do_import() -> bool {
        Args::parse().import
    }

    pub fn do_deposit() -> bool {
        Args::parse().deposit
    }

    pub fn get_import_args() -> (PathBuf, PathBuf, Option<PathBuf>, String) {
        let args = Args::parse();
        let keystore_path = args.keystore_path.expect("keystore path expected");
        let password_path = args.password_path.expect("password path expected");
        let slashing_db_path = args.slash_protection_path;
        let mrenclave = args.mrenclave.expect("--mrenclave missing");
        (keystore_path, password_path, slashing_db_path, mrenclave)
    }

    pub fn get_deposit_args() -> (String, String) {
        let args = Args::parse();
        let validator_pk_hex = args.validator_pk_hex.expect("Validator public key (hex) required for DepositData");
        let execution_addr = args.execution_addr.expect("ETH address (hex) required for withdrawal credentials");
        (validator_pk_hex, execution_addr)
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    Args::init_out_dir();
    let port = Args::port();

    println!("- Connecting to Secure-Signer on port {}", port);
    assert!(routes::is_alive(port).await.is_ok(), "Failed to reach Secure-Signer on port: {port}");
    println!("- Secure-Signer was reached!");

    if Args::do_keygen() {
        let resp = routes::bls_keygen(port).await.unwrap();
        // todo write to file
    }

    if Args::do_import() {
        let (keystore_path, password_path, slashing_db_path, mrenclave) =  Args::get_import_args(); 
        let resp = bls_import::import_from_files(
            port,
            keystore_path,
            password_path,
            slashing_db_path,
            &mrenclave
        )
        .await?;
        dbg!(resp);
    }

    if Args::do_deposit() {
        let (validator_pk_hex, execution_addr) = Args::get_deposit_args();
        let resp = deposit::get_deposit_signature(port, &validator_pk_hex, &execution_addr, &Args::config().fork_version).await?;
        let deposit_data_json = deposit::deposit_data_payload(resp, Args::config());
        dbg!(deposit_data_json);
        // todo write to file
    }

    Ok(())
}


    // println!("Starting Client");
    // assert!(routes::is_alive(9001).await.is_ok());

    // let resp = routes::bls_keygen(9001).await.unwrap();
    // dbg!(resp.pk_hex);

    // let resp = routes::list_bls_keys(9001).await.unwrap();
    // dbg!(resp.data);

    // let resp = routes::eth_keygen(9001).await.unwrap();
    // dbg!(resp.pk_hex);

    // let resp = routes::list_eth_keys(9001).await.unwrap();
    // dbg!(resp.data);
    // println!("Stopping Client");