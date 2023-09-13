extern crate puffersecuresigner;
use puffersecuresigner::{eth2::eth_types::Version, run, strip_0x_prefix};
use warp::Filter;

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
        "Starting SGX Guardian: localhost:{}, using genesis_fork_version: {:?}",
        port, genesis_fork_version
    );

    let routes = puffersecuresigner::api::upcheck_route()
        .or(puffersecuresigner::api::eth_keygen_route::eth_keygen_route())
        .or(puffersecuresigner::api::eth_keygen_route::eth_keygen_route_with_blockhash())
        .or(puffersecuresigner::api::getter_routes::list_eth_keys_route());

    let routes = routes
        .or(puffersecuresigner::api::eth_keygen_route::eth_keygen_route_with_blockhash_debug());

    run(port, routes).await;
}
