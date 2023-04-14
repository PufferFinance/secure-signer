mod routes;
mod bls_import;
mod deposit;

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

// impl Args {
//     pub fn init(&self) -> NetworkConfig {
//         let args = Args::parse();
//         let config = NetworkConfig::new(&args.config); 
//         (args, config)
//     }
// }


#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let dir = Path::new(&args.outdir);
    let dir_str = &dir.to_str().unwrap();
    fs::create_dir_all(dir);

    let config = NetworkConfig::new(&args.config); 

    let port = args.port;
    println!("- Connecting to Secure-Signer on port {}", port);
    assert!(routes::is_alive(port).await.is_ok(), "Failed to reach Secure-Signer on port: {port}");
    println!("- Secure-Signer was reached!");

    // ------- for generating BLS key in SS -------
    if args.bls_keygen {
        // todo write to file
    }

    // ------- for importing BLS key into SS -------
    if args.import.is_some() {

    }

    if args.deposit {
        let validator_pk_hex = args.validator_pk_hex.expect("Validator public key (hex) required for DepositData");
        let execution_addr = args.execution_addr.expect("ETH address (hex) required for withdrawal credentials");
        let resp = deposit::get_deposit_signature(port, &validator_pk_hex, &execution_addr, &config.fork_version).await?;
        let deposit_data_json = deposit::deposit_data_payload(resp, config.clone());
        dbg!(deposit_data_json);
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