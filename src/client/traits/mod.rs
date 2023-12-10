use async_trait::async_trait;

#[async_trait]
pub trait GuardianClientTrait {
    async fn health(&self) -> bool;

    async fn attest_fresh_eth_key(
        &self,
        blockhash: &str,
    ) -> anyhow::Result<crate::enclave::types::KeyGenResponse>;

    async fn list_eth_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse>;

    async fn validate_custody(
        &self,
        request: crate::enclave::types::ValidateCustodyRequest,
    ) -> anyhow::Result<crate::enclave::types::ValidateCustodyResponse>;

    async fn sign_exit(
        &self,
        request: crate::enclave::types::SignExitRequest,
    ) -> anyhow::Result<crate::enclave::types::SignExitResponse>;
}

#[async_trait]
pub trait ValidatorClientTrait {
    async fn health(&self) -> bool;

    async fn attest_fresh_bls_key(
        &self,
        payload: &crate::enclave::types::AttestFreshBlsKeyPayload,
    ) -> anyhow::Result<crate::enclave::types::BlsKeygenPayload>;

    async fn list_bls_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse>;

    async fn sign_voluntary_exit_message(
        &self,
        bls_pk_hex: String,
        epoch: crate::eth2::eth_types::Epoch,
        validator_index: crate::eth2::eth_types::ValidatorIndex,
        fork_info: crate::eth2::eth_types::ForkInfo,
    ) -> anyhow::Result<crate::enclave::types::SignatureResponse>;
}
