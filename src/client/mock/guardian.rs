use async_trait::async_trait;

use crate::client::traits::GuardianClientTrait;

#[derive(Clone, Debug, Default)]
pub struct MockGuardianClient {
    pub response_health: bool,
    pub response_attest_fresh_eth_key: Option<crate::enclave::types::KeyGenResponse>,
    pub response_list_eth_keys: Option<crate::enclave::types::ListKeysResponse>,
    pub response_validate_custody: Option<crate::enclave::types::ValidateCustodyResponse>,
    pub response_sign_exit: Option<crate::enclave::types::SignExitResponse>,
}

impl MockGuardianClient {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_health_response(&mut self, response: bool) {
        self.response_health = response;
    }
    pub fn set_attest_fresh_eth_key_response(
        &mut self,
        response: Option<crate::enclave::types::KeyGenResponse>,
    ) {
        self.response_attest_fresh_eth_key = response;
    }
    pub fn set_list_eth_keys_response(
        &mut self,
        response: Option<crate::enclave::types::ListKeysResponse>,
    ) {
        self.response_list_eth_keys = response;
    }
    pub fn set_validate_custody_response(
        &mut self,
        response: Option<crate::enclave::types::ValidateCustodyResponse>,
    ) {
        self.response_validate_custody = response;
    }
    pub fn set_sign_exit_response(
        &mut self,
        response: Option<crate::enclave::types::SignExitResponse>,
    ) {
        self.response_sign_exit = response;
    }
}

#[async_trait]
impl GuardianClientTrait for MockGuardianClient {
    async fn health(&self) -> bool {
        self.response_health
    }

    async fn attest_fresh_eth_key(
        &self,
        blockhash: &str,
    ) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        match self.response_attest_fresh_eth_key.clone() {
            Some(res) => Ok(res),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }

    async fn list_eth_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        match self.response_list_eth_keys.clone() {
            Some(res) => Ok(res),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }

    async fn validate_custody(
        &self,
        request: crate::enclave::types::ValidateCustodyRequest,
    ) -> anyhow::Result<crate::enclave::types::ValidateCustodyResponse> {
        match self.response_validate_custody.clone() {
            Some(res) => Ok(res),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }

    async fn sign_exit(
        &self,
        request: crate::enclave::types::SignExitRequest,
    ) -> anyhow::Result<crate::enclave::types::SignExitResponse> {
        match self.response_sign_exit.clone() {
            Some(res) => Ok(res),
            None => {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AAA".to_string()).into())
            }
        }
    }
}
