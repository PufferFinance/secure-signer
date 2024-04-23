pub mod handlers;
use anyhow::{bail, Result};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use log::{error, info};
use sha3::Digest;

use crate::eth2::eth_signing::BLSSignMsg;

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn sign_validator_message(
    Path(bls_pk_hex): Path<String>,
    State(state): State<crate::enclave::shared::handlers::AppState>,
    Json(req): Json<crate::eth2::eth_signing::BLSSignMsg>,
) -> axum::response::Response {
    info!("secure_sign_bls()");

    if let BLSSignMsg::DEPOSIT(_) = req {
        return (
            axum::http::status::StatusCode::BAD_REQUEST,
            format!("Signing deposit message not allowed"),
        )
            .into_response();
    }

    // Sanitize the input bls_pk_hex
    let bls_pk_hex = match crate::crypto::bls_keys::sanitize_bls_pk_hex(&bls_pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Bad BLS public key format: {bls_pk_hex}");
            return (
                axum::http::status::StatusCode::BAD_REQUEST,
                format!("Bad bls_pk_hex, {:?}", e),
            )
                .into_response();
        }
    };

    info!("Request for validator pubkey: {bls_pk_hex}");
    info!("Request:\n{:#?}", serde_json::to_string_pretty(&req));

    // Verify not a slashable msg
    match crate::enclave::shared::is_slashable(&bls_pk_hex, &req) {
        Ok(b) => match b {
            true => {
                return (
                    axum::http::status::StatusCode::PRECONDITION_FAILED,
                    format!("Signing operation failed due to slashing protection rules"),
                )
                    .into_response()
            }
            false => {}
        },
        Err(e) => {
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response()
        }
    };

    // Compute the msg to be signed
    let signing_root: crate::eth2::eth_types::Root =
        req.to_signing_root(Some(state.genesis_fork_version));
    info!("signing_root: {}", hex::encode(signing_root));

    // Update the slash protection DB if msg was a block or attestation
    if req.can_be_slashed() {
        if let Err(e) = crate::enclave::shared::update_slash_protection_db(&bls_pk_hex, &req) {
            error!("Failed trying to update slash protection database");
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response();
        }
    }

    // Sign the message
    match crate::crypto::bls_keys::bls_agg_sign_from_saved_sk(&bls_pk_hex, &signing_root) {
        Ok(sig) => {
            info!("signature: {:?}", hex::encode(sig.to_bytes()));
            let response = crate::enclave::types::SignatureResponse::new(&sig.to_bytes());
            (axum::http::status::StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed trying to sign");
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response();
        }
    }
}

/// Returns true if signing_data is a block proposal or attestation and is slashable
fn is_slashable(
    bls_pk_hex: &String,
    signing_data: &crate::eth2::eth_signing::BLSSignMsg,
) -> Result<bool> {
    // The slashing DB must exist
    let db: crate::eth2::slash_protection::SlashingProtectionData =
        crate::eth2::slash_protection::SlashingProtectionData::read(bls_pk_hex.as_str())?;

    match signing_data {
        crate::eth2::eth_signing::BLSSignMsg::BLOCK(m)
        | crate::eth2::eth_signing::BLSSignMsg::block(m) => {
            Ok(db.is_slashable_block_slot(m.block.slot))
        }
        crate::eth2::eth_signing::BLSSignMsg::BLOCK_V2(m)
        | crate::eth2::eth_signing::BLSSignMsg::block_v2(m) => {
            Ok(db.is_slashable_block_slot(m.beacon_block.block_header.slot))
        }

        crate::eth2::eth_signing::BLSSignMsg::ATTESTATION(m)
        | crate::eth2::eth_signing::BLSSignMsg::attestation(m) => Ok(db
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

fn update_slash_protection_db(
    bls_pk_hex: &String,
    signing_data: &crate::eth2::eth_signing::BLSSignMsg,
) -> Result<()> {
    info!("update_slash_protection_db()");
    let mut db: crate::eth2::slash_protection::SlashingProtectionData =
        crate::eth2::slash_protection::SlashingProtectionData::read(bls_pk_hex.as_str())?;
    let signing_root = signing_data.to_signing_root(None);
    match signing_data {
        crate::eth2::eth_signing::BLSSignMsg::BLOCK(m)
        | crate::eth2::eth_signing::BLSSignMsg::block(m) => {
            let b = crate::eth2::slash_protection::SignedBlockSlot {
                slot: m.block.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        crate::eth2::eth_signing::BLSSignMsg::BLOCK_V2(m)
        | crate::eth2::eth_signing::BLSSignMsg::block_v2(m) => {
            let b = crate::eth2::slash_protection::SignedBlockSlot {
                slot: m.beacon_block.block_header.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        crate::eth2::eth_signing::BLSSignMsg::ATTESTATION(m)
        | crate::eth2::eth_signing::BLSSignMsg::attestation(m) => {
            let a = crate::eth2::slash_protection::SignedAttestationEpochs {
                source_epoch: m.attestation.source.epoch,
                target_epoch: m.attestation.target.epoch,
                signing_root: Some(signing_root),
            };
            db.new_attestation(a, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        _ => {
            // Only block proposals and attestations are slashable
            error!("Attempted to update slash protection db with non-slashable msg type");
            bail!("Should not update slash protection db for non blocks/attestations")
        }
    }
}

pub fn build_validator_remote_attestation_payload(
    validator_pk_set: blsttc::PublicKeySet,
    signature: &crate::eth2::eth_types::BLSSignature,
    deposit_data_root: &crate::eth2::eth_types::Root,
    enc_sk_shares: Vec<String>,
    guardian_pks: Vec<ecies::PublicKey>,
) -> Result<Vec<u8>> {
    let mut hasher = sha3::Keccak256::new();

    // blsPubKeySet
    hasher.update(validator_pk_set.to_bytes());

    // blsPubKey
    hasher.update(validator_pk_set.public_key().to_bytes());

    // signature
    hasher.update(signature.to_vec());

    // depositDataRoot
    hasher.update(deposit_data_root);

    for (i, (sk_share, g_pk)) in enc_sk_shares.iter().zip(guardian_pks.iter()).enumerate() {
        // blsEncPrivKeyShares
        hasher.update(hex::decode(&sk_share)?);

        // blsPubKeyShares
        hasher.update(&validator_pk_set.public_key_share(i).to_bytes());

        // guardianPubKeys
        hasher.update(&g_pk.serialize());
    }

    // threshold
    hasher.update(validator_pk_set.threshold().to_be_bytes());

    let digest: [u8; 32] = hasher.finalize().into();

    let mut padded: Vec<u8> = Vec::with_capacity(64);

    // Copy the elements from the array to the Vec
    padded.extend_from_slice(&digest);

    // Pad with zeros to make the Vec length 64
    padded.extend(vec![0; 32]);

    Ok(padded)
}
