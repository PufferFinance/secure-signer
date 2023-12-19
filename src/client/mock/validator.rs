use async_trait::async_trait;

use crate::client::traits::ValidatorClientTrait;
use crate::enclave::types::ListKeysResponse;

#[derive(Clone, Debug, Default)]
pub struct MockValidatorClient {
    pub health: bool,
    pub fresh_bls_key: Option<crate::enclave::types::BlsKeygenPayload>,
    pub voluntary_exit_message: Option<crate::enclave::types::SignatureResponse>,
}

impl MockValidatorClient {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_health_response(&mut self, response: bool) {
        self.health = response;
    }
}

#[async_trait]
impl ValidatorClientTrait for MockValidatorClient {
    async fn health(&self) -> bool {
        self.health
    }

    async fn attest_fresh_bls_key(
        &self,
        payload: &crate::enclave::types::AttestFreshBlsKeyPayload,
    ) -> anyhow::Result<crate::enclave::types::BlsKeygenPayload> {
        match self.fresh_bls_key.as_ref() {
            Some(resp) => Ok(resp.clone()),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }

    async fn list_bls_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        Ok(ListKeysResponse { data: vec![] })
    }

    async fn sign_voluntary_exit_message(
        &self,
        bls_pk_hex: String,
        epoch: crate::eth2::eth_types::Epoch,
        validator_index: crate::eth2::eth_types::ValidatorIndex,
        fork_info: crate::eth2::eth_types::ForkInfo,
    ) -> anyhow::Result<crate::enclave::types::SignatureResponse> {
        match self.voluntary_exit_message.as_ref() {
            Some(resp) => Ok(resp.clone()),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }
}
