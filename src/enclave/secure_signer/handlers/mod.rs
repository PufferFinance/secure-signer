pub mod bls_keygen;
pub mod eth_keygen;
pub mod secure_sign_bls;
pub mod validator_deposit;

#[derive(Clone)]
pub struct AppState {
    pub genesis_fork_version: crate::eth2::eth_types::Version,
}
