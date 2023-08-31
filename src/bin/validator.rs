extern crate puffersecuresigner;
use puffersecuresigner::{eth2::eth_types::Version, run, strip_0x_prefix};

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .unwrap_or("3031".into())
        .parse::<u16>()
        .expect("BAD PORT");
    let genesis_fork_version_str: String =
        std::env::args().nth(2).unwrap_or("00000000".to_string());
    let genesis_fork_version_str: String = strip_0x_prefix!(genesis_fork_version_str);
    let mut genesis_fork_version = Version::default();
    genesis_fork_version.copy_from_slice(
        &hex::decode(&genesis_fork_version_str).expect("Bad genesis_fork_version"),
    );

    println!(
        "Starting SGX Validator: localhost:{}, using genesis_fork_version: {:?}",
        port, genesis_fork_version
    );

    let routes = puffersecuresigner::api::upcheck_route();
    run(port, routes).await;
}
