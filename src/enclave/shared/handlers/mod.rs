pub mod health;
pub mod secure_sign_bls;
pub mod list_bls_keys;
pub mod list_eth_keys;


#[derive(Clone)]
pub struct AppState {
    pub genesis_fork_version: crate::eth2::eth_types::Version,
}