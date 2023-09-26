use anyhow::anyhow;
use axum::async_trait;

mod methods;
mod secure_signer;
mod tests;

#[async_trait]
pub trait Method {
    type Response;

    async fn handle<'a>(self, client: &'a Client) -> anyhow::Result<Self::Response>;
}

#[async_trait]
impl Method for ValidatorMethod {
    type Response = ValidatorResponse;

    async fn handle<'a>(self, client: &'a Client) -> anyhow::Result<Self::Response> {
        todo!()
    }
}

#[async_trait]
impl Method for GuardianMethod {
    type Response = GuardianResponse;

    async fn handle<'a>(self, client: &'a Client) -> anyhow::Result<Self::Response> {
        todo!()
    }
}

#[derive(Debug)]
pub enum ValidatorMethod {
    Health,
    AttestFreshBlsKey(ValidatorFreshBlshKeyData),
    ListKeys,
}

#[derive(Debug)]
pub enum SecureSignerMethod {
    Health,
    GenerateEthKey,
    GenerateBlsKey,
    ListEthKeys,
    ListBlsKeys,
}

#[derive(Debug)]
pub enum GuardianMethod {
    Health,
    ValidateCustody(ValidateCustodyData),
    AttestFreshEthKey(Blockhash),
    ListKeys,
}

#[derive(Debug)]
pub enum ValidatorResponse {
    Health,
    AttestFreshBlsKey(ValidatorFreshBlshKeyData),
    ListKeys,
}

#[derive(Debug)]
pub enum SecureSignerResponse {
    Health,
    GenerateEthKey,
    GenerateBlsKey,
    ListEthKeys,
    ListBlsKeys,
}

#[derive(Debug)]
pub enum GuardianResponse {
    Health,
    ValidateCustody(ValidateCustodyData),
    AttestFreshEthKey(Blockhash),
    ListKeys,
}

pub struct Client {
    http_client: reqwest::Client,
    network_config: NetworkConfig,
    validator_url: String,
    secure_signer_url: String,
    guardian_url: String,
}

fn default_client_guardian_url() -> String {
    "http://localhost:9002".to_string()
}
fn default_client_validator_url() -> String {
    "http://localhost:9003".to_string()
}
fn default_client_secure_signer_url() -> String {
    "http://localhost:9001".to_string()
}

impl Client {
    pub async fn call<M: Method>(self, method: M) -> anyhow::Result<M::Response> {
        method.handle(&self).await
    }
}

pub struct ClientBuilder {
    network_config: Option<NetworkConfig>,
    validator_url: Option<String>,
    secure_signer_url: Option<String>,
    guardian_url: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            network_config: None,
            validator_url: None,
            secure_signer_url: None,
            guardian_url: None,
        }
    }

    pub fn build(self) -> Client {
        Client {
            http_client: reqwest::Client::new(),
            network_config: self.network_config.unwrap_or(NetworkConfig::default()),
            validator_url: self.validator_url.unwrap_or(default_client_validator_url()),
            secure_signer_url: self
                .secure_signer_url
                .unwrap_or(default_client_secure_signer_url()),
            guardian_url: self.guardian_url.unwrap_or(default_client_guardian_url()),
        }
    }

    pub fn network_config(mut self, config: NetworkConfig) -> ClientBuilder {
        self.network_config = Some(config);
        self
    }

    pub fn validator_url(mut self, url: String) -> ClientBuilder {
        self.validator_url = Some(url);
        self
    }
    pub fn guardian_url(mut self, url: String) -> ClientBuilder {
        self.guardian_url = Some(url);
        self
    }
    pub fn secure_signer_url(mut self, url: String) -> ClientBuilder {
        self.secure_signer_url = Some(url);
        self
    }
}

#[derive(Debug)]
pub struct ValidatorFreshBlshKeyData {}

#[derive(Debug)]
pub struct ValidateCustodyData {}

#[derive(Default)]
pub struct NetworkConfig {}
type Blockhash = String;
