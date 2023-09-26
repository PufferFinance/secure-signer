use crate::routes::bls_sign;

use super::NetworkConfig;
use anyhow::Result;
use puffersecuresigner::eth2::eth_signing::BLSSignMsg;
use puffersecuresigner::eth2::eth_types::SignedVoluntaryExit;
use puffersecuresigner::eth2::eth_types::{VoluntaryExit, VoluntaryExitRequest};

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
