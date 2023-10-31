pub mod attest_fresh_bls_key;

#[derive(Clone)]
pub struct AppState {
    pub genesis_fork_version: crate::eth2::eth_types::Version,
}
