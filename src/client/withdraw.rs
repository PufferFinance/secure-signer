use crate::routes::bls_sign;

use super::routes;
use super::NetworkConfig;
use anyhow::Context;
use anyhow::{bail, Result};
use puffersecuresigner::eth2::eth_signing::BLSSignMsg;
use puffersecuresigner::eth2::eth_types::SignedVoluntaryExit;
use puffersecuresigner::eth2::eth_types::{Fork, ForkInfo, VoluntaryExit, VoluntaryExitRequest};
use puffersecuresigner::{
    constants::BLS_PUB_KEY_BYTES,
    eth2::eth_types::{DepositMessage, DepositRequest, DepositResponse, Version},
    strip_0x_prefix,
};
use serde_json::Value;

pub async fn exit_validator(
    port: u16,
    validator_pk_hex: &str,
    epoch: u64,
    validator_index: u64,
    config: NetworkConfig,
) -> Result<SignedVoluntaryExit> {
    let vem = VoluntaryExitRequest {
        signingRoot: None,
        fork_info: config.fork_info,
        voluntary_exit: VoluntaryExit {
            epoch,
            validator_index,
        },
    };
    let req = BLSSignMsg::VOLUNTARY_EXIT(vem);
    let json = serde_json::to_string(&req)?;
    let sig = bls_sign(port, &json, &validator_pk_hex.to_string()).await?;
    Ok(SignedVoluntaryExit {
        message: VoluntaryExit {
            epoch,
            validator_index,
        },
        signature: sig.to_ssz_bytes()?,
    })
}
