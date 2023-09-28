use std::sync::Arc;

use self::{
    guardian::GuardianClient, secure_signer::SecureSignerClient, validator::ValidatorClient,
};

mod guardian;
mod secure_signer;
mod tests;
mod validator;

pub struct Client {
    pub validator: ValidatorClient,
    pub secure_signer: SecureSignerClient,
    pub guardian: GuardianClient,
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

pub struct ClientBuilder {
    validator_url: Option<String>,
    secure_signer_url: Option<String>,
    guardian_url: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            validator_url: None,
            secure_signer_url: None,
            guardian_url: None,
        }
    }

    pub fn build(self) -> Client {
        let client = Arc::new(reqwest::Client::new());
        Client {
            validator: ValidatorClient {
                url: self.validator_url.unwrap_or(default_client_validator_url()),
                client: client.clone(),
            },
            guardian: GuardianClient {
                url: self
                    .secure_signer_url
                    .unwrap_or(default_client_guardian_url()),
                client: client.clone(),
            },
            secure_signer: SecureSignerClient {
                url: self
                    .guardian_url
                    .unwrap_or(default_client_secure_signer_url()),
                client: client.clone(),
            },
        }
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
