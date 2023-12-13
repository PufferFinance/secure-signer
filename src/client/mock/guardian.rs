use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::client::traits::GuardianClientTrait;

#[derive(Clone, Debug, Default)]
pub struct MockGuardianClient {
    pub health_responses: Arc<Mutex<VecDeque<bool>>>,
    pub attest_fresh_eth_key_responses: Arc<Mutex<VecDeque<crate::enclave::types::KeyGenResponse>>>,
    pub list_eth_keys_responses: Arc<Mutex<VecDeque<crate::enclave::types::ListKeysResponse>>>,
    pub validate_custody_responses: Arc<Mutex<VecDeque<crate::enclave::types::ValidateCustodyResponse>>>,
    pub sign_exit_responses: Arc<Mutex<VecDeque<crate::enclave::types::SignExitResponse>>>,
}

impl MockGuardianClient {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_health_response(&mut self, value: bool) {
        self.health_responses.lock().unwrap().push_back(value);
    }
    pub fn push_attest_fresh_eth_key_response(
        &mut self,
        value: crate::enclave::types::KeyGenResponse,
    ) {
        self.attest_fresh_eth_key_responses.lock().unwrap().push_back(value);
    }
    pub fn push_list_eth_keys_response(
        &mut self,
        value: crate::enclave::types::ListKeysResponse,
    ) {
        self.list_eth_keys_responses.lock().unwrap().push_back(value);
    }
    pub fn push_validate_custody_response(
        &mut self,
        value: crate::enclave::types::ValidateCustodyResponse,
    ) {
        self.validate_custody_responses.lock().unwrap().push_back(value);
    }
    pub fn push_sign_exit_response(
        &mut self,
        value: crate::enclave::types::SignExitResponse,
    ) {
        self.sign_exit_responses.lock().unwrap().push_back(value);
    }
}

#[async_trait]
impl GuardianClientTrait for MockGuardianClient {
    async fn health(&self) -> bool {
        match self.health_responses.lock().unwrap().pop_front() {
            Some(value) => value,
            None => false,
        }
    }

    async fn attest_fresh_eth_key(
        &self,
        blockhash: &str,
    ) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        match self.attest_fresh_eth_key_responses.lock().unwrap().pop_front() {
            Some(res) => Ok(res),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "No response set".to_string(),
            )
            .into()),
        }
    }

    async fn list_eth_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        match self.list_eth_keys_responses.lock().unwrap().pop_front() {
            Some(res) => Ok(res),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "No response set".to_string(),
            )
            .into()),
        }
    }

    async fn validate_custody(
        &self,
        request: crate::enclave::types::ValidateCustodyRequest,
    ) -> anyhow::Result<crate::enclave::types::ValidateCustodyResponse> {
        match self.validate_custody_responses.lock().unwrap().pop_front() {
            Some(res) => Ok(res),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "No response set".to_string(),
            )
            .into()),
        }
    }

    async fn sign_exit(
        &self,
        request: crate::enclave::types::SignExitRequest,
    ) -> anyhow::Result<crate::enclave::types::SignExitResponse> {
        match self.sign_exit_responses.lock().unwrap().pop_front() {
            Some(res) => Ok(res),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "No response set".to_string(),
            )
            .into()),
        }
    }
}
