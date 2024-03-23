pub mod health;
pub mod list_bls_keys;
pub mod list_bls_keys_for_vc;
pub mod list_eth_keys;
pub mod secure_sign_bls;

#[derive(Clone)]
pub struct AppState {
    pub genesis_fork_version: crate::eth2::eth_types::Version,
}
