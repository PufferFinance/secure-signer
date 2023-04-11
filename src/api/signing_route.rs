use super::helpers::{error_response, signature_success_response};
use crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB;
use crate::crypto::bls_keys;
use crate::eth2::eth_signing::*;
use crate::eth2::eth_types::*;
use crate::eth2::slash_protection::{
    SignedAttestationEpochs, SignedBlockSlot, SlashingProtectionData,
};
use crate::strip_0x_prefix;
use anyhow::{bail, Result};
use log::{debug, error, info};
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// BLS signs a valid Eth2 message if it is not slashable
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn bls_sign_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("v1"))
        .and(warp::path("eth2"))
        .and(warp::path("sign"))
        .and(warp::path::param())
        .and(warp::body::bytes())
        .and_then(secure_sign_bls)
}

/// Returns true if signing_data is a block proposal or attestation and is slashable
fn is_slashable(bls_pk_hex: &String, signing_data: &BLSSignMsg) -> Result<bool> {
    // The slashing DB must exist
    let db: SlashingProtectionData = SlashingProtectionData::read(bls_pk_hex.as_str())?;

    match signing_data {
        BLSSignMsg::BLOCK(m) | BLSSignMsg::block(m) => Ok(db.is_slashable_block_slot(m.block.slot)),
        BLSSignMsg::BLOCK_V2(m) | BLSSignMsg::block_v2(m) => {
            Ok(db.is_slashable_block_slot(m.beacon_block.block_header.slot))
        }

        BLSSignMsg::ATTESTATION(m) | BLSSignMsg::attestation(m) => Ok(db
            .is_slashable_attestation_epochs(
                m.attestation.source.epoch,
                m.attestation.target.epoch,
            )),
        _ => {
            // Only block proposals and attestations are slashable
            Ok(false)
        }
    }
}

fn update_slash_protection_db(bls_pk_hex: &String, signing_data: &BLSSignMsg) -> Result<()> {
    info!("update_slash_protection_db");
    let mut db: SlashingProtectionData = SlashingProtectionData::read(bls_pk_hex.as_str())?;
    let signing_root = signing_data.to_signing_root();
    match signing_data {
        BLSSignMsg::BLOCK(m) => {
            let b = SignedBlockSlot {
                slot: m.block.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        BLSSignMsg::BLOCK_V2(m) => {
            let b = SignedBlockSlot {
                slot: m.beacon_block.block_header.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        BLSSignMsg::ATTESTATION(m) => {
            let a = SignedAttestationEpochs {
                source_epoch: m.attestation.source.epoch,
                target_epoch: m.attestation.target.epoch,
                signing_root: Some(signing_root),
            };
            db.new_attestation(a, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        _ => {
            // Only block proposals and attestations are slashable
            error!("Attempted to update slash protection db with non-slashable msg type");
            bail!("Should not update slash protection db for non blocks/attestations")
        }
    }
}

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
async fn secure_sign_bls(
    bls_pk_hex: String,
    req: bytes::Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Deserialize the request to a BLSSignMsg type
    let req: BLSSignMsg = match serde_json::from_slice(&req) {
        Ok(req) => req,
        Err(e) => {
            return Ok(error_response(
                &format!("Malformed signing data, {:?}", e),
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // Sanitize the input bls_pk_hex
    let bls_pk_hex = match bls_keys::sanitize_bls_pk_hex(&bls_pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(error_response(
                &format!("Bad bls_pk_hex, {:?}", e),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    // info!("Validator pubkey {bls_pk_hex}");
    // info!("Request:\n{:#?}", req);

    // Verify not a slashable msg
    match is_slashable(&bls_pk_hex, &req) {
        Ok(b) => match b {
            true => {
                return Ok(error_response(
                    &format!("Signing operation failed due to slashing protection rules"),
                    StatusCode::PRECONDITION_FAILED,
                ));
            }
            false => {}
        },
        Err(e) => {
            return Ok(error_response(
                &format!("Signing operation failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    // Compute the msg to be signed
    let signing_root: Root = req.to_signing_root();

    // Update the slash protection DB if msg was a block or attestation
    if req.can_be_slashed() {
        match update_slash_protection_db(&bls_pk_hex, &req) {
            Ok(()) => {}
            Err(e) => {
                return Ok(error_response(
                    &format!("Signing operation failed: {:?}", e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    }

    let signature = match bls_keys::bls_agg_sign_from_saved_sk(&bls_pk_hex, &signing_root) {
        Ok(sk) => sk,
        Err(e) => {
            return Ok(error_response(
                &format!("Signing operation failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    };

    Ok(signature_success_response(&signature.to_bytes()))
}
