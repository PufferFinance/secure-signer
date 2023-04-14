use super::routes;
use super::NetworkConfig;
use anyhow::Context;
use anyhow::{bail, Result};
use puffersecuresigner::{
    constants::BLS_PUB_KEY_BYTES,
    eth2::eth_types::{DepositMessage, DepositRequest, DepositResponse, Version},
    strip_0x_prefix,
};
use serde_json::Value;

const DEPOSIT_AMOUNT: u64 = 32000000000;

fn eth_addr_to_credentials(execution_addr: &str) -> Result<String> {
    let addr: String = strip_0x_prefix!(execution_addr);
    if addr.len() != 40 {
        bail!("Invalid length ETH address")
    }
    let withdrawal_credentials = format!("0x010000000000000000000000{addr}");
    assert_eq!(withdrawal_credentials.len(), 66);
    Ok(withdrawal_credentials)
}

fn build_deposit_request(
    validator_pk_hex: &str,
    withdrawal_credentials: &str,
    fork_version: Version,
) -> Result<DepositRequest> {
    let validator_pk_hex: String = strip_0x_prefix!(validator_pk_hex);
    let pk_bytes = hex::decode(validator_pk_hex)?;
    assert_eq!(
        pk_bytes.len(),
        BLS_PUB_KEY_BYTES,
        "Invalid bls public key length"
    );

    let withdrawal_credentials: String = strip_0x_prefix!(withdrawal_credentials);
    let withdrawal_bytes = hex::decode(withdrawal_credentials)?;
    assert_eq!(
        withdrawal_bytes.len(),
        32,
        "Invalid withdrawal credentials length"
    );
    let mut withdrawal_fixed_bytes: [u8; 32] = [0_u8; 32];
    withdrawal_fixed_bytes.clone_from_slice(&withdrawal_bytes);

    let deposit = DepositMessage {
        pubkey: pk_bytes.into(),
        withdrawal_credentials: withdrawal_fixed_bytes,
        amount: DEPOSIT_AMOUNT,
    };

    let msg = DepositRequest {
        signingRoot: None,
        deposit,
        genesis_fork_version: fork_version,
    };

    Ok(msg)
}

pub async fn get_deposit_signature(
    port: u16,
    bls_pk_hex: &str,
    execution_addr: &str,
    fork_version: Version,
) -> Result<DepositResponse> {
    let withdrawal_creds = eth_addr_to_credentials(execution_addr)?;
    let deposit_req = build_deposit_request(bls_pk_hex, &withdrawal_creds, fork_version)?;
    let json_req = serde_json::to_string(&deposit_req)?;
    let resp = routes::deposit(port, &json_req).await?;
    Ok(resp)
}

pub fn deposit_data_payload(d: DepositResponse, config: NetworkConfig) -> Result<Value> {
    let pubkey = d.pubkey;
    let withdrawal_credentials = d.withdrawal_credentials;
    let amount = d.amount;
    let signature = d.signature;
    let deposit_message_root = d.deposit_message_root;
    let deposit_data_root = d.deposit_data_root;
    let network_name = config.network_name;
    let fork_version = hex::encode(config.fork_info.fork.current_version);
    let deposit_cli_version = config.deposit_cli_version;

    // Build deposit JSON that works with https://goerli.launchpad.ethereum.org/en/upload-deposit-data
    let json_string = format!(
        r#"
        [{{
            "pubkey": "{pubkey}",
            "withdrawal_credentials": "{withdrawal_credentials}",
            "amount": {amount},
            "signature": "{signature}",
            "deposit_message_root": "{deposit_message_root}",
            "deposit_data_root": "{deposit_data_root}",
            "fork_version": "{fork_version}",
            "network_name": "{network_name}",
            "deposit_cli_version": "{deposit_cli_version}"
        }}]"#
    );
    serde_json::from_str(&json_string).with_context(|| "Failed to serialize final DepositData json")
}
