use super::helpers::{error_response, success_response};
use super::{KeyImportResponse, KeyImportRequest};
use crate::constants::BLS_PRIV_KEY_BYTES;
use crate::crypto::bls_keys;
use crate::eth2::slash_protection::{SlashingProtectionData, SlashingProtectionDB};
use crate::crypto::{eth_keys, keystore::import_keystore};
use anyhow::{Result, bail};
use blsttc::SecretKeySet;
use log::{info, error};
use ssz::Encode;
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// Imports a BLS private key to the Enclave. 
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager
pub fn bls_key_import_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and(warp::body::json::<KeyImportRequest>())
        .and_then(bls_key_import_service)
}

/// Decrypts a BLS keystore where the password was encrypted via ECDH with an SECP256K1 key
/// safeguarded by the TEE, then saves the bls key to enclave memory. Expects the 
/// ETH encrypting_pk_hex to be compressed (33 bytes) and hex-encoded. 
pub fn decrypt_and_save_imported_bls_key(req: &KeyImportRequest) -> Result<String> {
    // Decrypt bls secret key from keystore json
    let eth_sk = eth_keys::fetch_eth_key(&req.encrypting_pk_hex)?;
    let sk_bytes = import_keystore(&req.keystore, &req.ct_password_hex, &eth_sk)?;

    if sk_bytes.len() != BLS_PRIV_KEY_BYTES {
        bail!("Keystore does not contain {BLS_PRIV_KEY_BYTES}B key!");
    }

    let sk = SecretKeySet::from_bytes(sk_bytes)?;

    // Get the public key: 
    let pk = sk.public_keys().public_key();
    let pk_hex = pk.to_hex();

    // Add a slash protection entry for this pub key
    match &req.slashing_protection {
        None => {
            // Generate fresh slashing protection
            let db = SlashingProtectionData::from_pk_hex(&pk_hex)?;
            db.write()?;
        },
        Some(sp) => {
            // Verify the supplied slash protection matches the pk
            let db: SlashingProtectionDB = serde_json::from_str(sp)?;
            // KNOWN LIMITATION: Only support one keystore
            match db.data.first() {
                None => {
                    // Generate fresh slashing protection
                    let db = SlashingProtectionData::from_pk_hex(&pk_hex)?;
                    db.write()?;
                }, 
                Some(data) => {
                    if hex::encode(data.pubkey.as_ssz_bytes()) == pk_hex {
                        data.write()?
                    } else {
                        error!("The slashing protection pubkey does not match keystore");
                        bail!("The slashing protection pubkey does not match keystore")
                    }
                }
            }
        }
    }
    
    // Save the BLS key to enclave memory
    bls_keys::save_bls_key(&sk)?;
    info!("Imported BLS keystore with pk: {pk_hex}");

    Ok(pk_hex)
}

/// Decrypts and saves an incoming encrypted BLS key. Returns a `KeyImportResponse` on success.
pub async fn bls_key_import_service(
    req: KeyImportRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("bls_key_import_service()");
    match decrypt_and_save_imported_bls_key(&req) {
        Ok(bls_pk_hex) => {
            // The key has successfully been saved, formulate http response
            let resp = KeyImportResponse::new(bls_pk_hex);
            Ok(success_response(&resp))
        }
        Err(e) => {
            return Ok(error_response(
                &format!("bls_key_import_service failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}