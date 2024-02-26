use std::sync::Arc;

use async_trait::async_trait;

use crate::strip_0x_prefix;

use crate::client::traits::ValidatorClientTrait;

pub struct ValidatorClient {
    pub url: String,
    pub client: Arc<reqwest::Client>,
}

#[async_trait]
impl ValidatorClientTrait for ValidatorClient {
    async fn health(&self) -> bool {
        let Ok(resp) = self
            .client
            .get(format!("{}/upcheck", self.url))
            .send()
            .await
        else {
            return false;
        };
        resp.status() == reqwest::StatusCode::OK
    }

    async fn attest_fresh_bls_key(
        &self,
        payload: &crate::enclave::types::AttestFreshBlsKeyPayload,
    ) -> anyhow::Result<crate::enclave::types::BlsKeygenPayload> {
        let resp = self
            .client
            .post(format!("{}/bls/v1/keygen", self.url))
            .json(payload)
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }

    async fn list_bls_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        let resp = self
            .client
            .get(format!("{}/eth/v1/keystores", self.url))
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }

    async fn sign_voluntary_exit_message(
        &self,
        bls_pk_hex: String,
        epoch: crate::eth2::eth_types::Epoch,
        validator_index: crate::eth2::eth_types::ValidatorIndex,
        fork_info: crate::eth2::eth_types::ForkInfo,
    ) -> anyhow::Result<crate::enclave::types::SignatureResponse> {
        let bls_pk_hex: String = strip_0x_prefix!(bls_pk_hex);
        let vem = crate::eth2::eth_types::VoluntaryExitRequest {
            signingRoot: None,
            fork_info: fork_info,
            voluntary_exit: crate::eth2::eth_types::VoluntaryExit {
                epoch,
                validator_index,
            },
        };
        let req = crate::eth2::eth_signing::BLSSignMsg::VOLUNTARY_EXIT(vem);

        let resp = self
            .client
            .post(format!("{}/api/v1/eth2/sign/{}", self.url, bls_pk_hex))
            .json(&req)
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }
}
