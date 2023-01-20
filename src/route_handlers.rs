use crate::eth_signing::*;
use crate::eth_types::*;
use crate::keys::load_then_save_keystore;
use crate::keys::{
    bls_key_gen, eth_key_gen, list_eth_keys, list_generated_bls_keys,
    list_imported_bls_keys, read_eth_key, write_key, new_keystore
};
use crate::remote_attestation::{epid_remote_attestation, AttestationEvidence};

use anyhow::Context;
use anyhow::{bail, Result};
use blst::min_pk::PublicKey;
use blst::min_pk::SecretKey;
use ecies::{decrypt, PublicKey as EthPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use warp::{http::StatusCode, reply};
use std::path::Path;

#[derive(Deserialize, Serialize, Debug)]
pub struct RemoteAttestationRequest {
    pub pub_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RemoteAttestationResponse {
    pub pub_key: String,
    pub evidence: AttestationEvidence,
}

/// Performs remote attestation, committing to the supplied public key (SECP256K1 or BLS) 
/// iff the key's corresponding private key already exists in enclave. Returns a `RemoteAttestationResponse` on success.
pub async fn epid_remote_attestation_service(
    pk_hex: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    match epid_remote_attestation(&pk_hex) {
        Ok(evidence) => {
            let resp = RemoteAttestationResponse {
                pub_key: pk_hex,
                evidence: evidence,
            };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys
            .iter()
            .map(|pk| {
                // Prepend leading 0x if needed
                let pubkey = match pk[0..2].into() {
                    "0x" => pk.to_string(),
                    _ => "0x".to_owned() + &pk.to_string(),
                };
                ListKeysResponseInner {
                    pubkey: pubkey.into(),
                }
            })
            .collect();

        ListKeysResponse { data: inners }
    }
}

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn bls_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    println!("log: bls_key_gen_service()");
    let save_key = true;
    match bls_key_gen(save_key) {
        Ok(pk) => {
            let resp = KeyGenResponse::from_bls_key(pk);
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}


#[derive(Debug, Deserialize, Serialize)]
pub struct KeyGenResponse {
    pub pk_hex: String,
}

impl KeyGenResponse {
    pub fn from_eth_key(pk: EthPublicKey) -> Self {
        KeyGenResponse {
            pk_hex: format!("0x{}", hex::encode(pk.serialize_compressed()))
        }
    }

    pub fn from_bls_key(pk: PublicKey) -> Self {
        KeyGenResponse {
            pk_hex: format!("0x{}", hex::encode(&pk.compress()))
        }
    }
}

/// Runs all the logic to generate and save a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn eth_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    println!("log: eth_key_gen_service()");
    match eth_key_gen() {
        Ok(pk) => {
            let resp = KeyGenResponse::from_eth_key(pk);
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Lists the public keys of the imported BLS secret keys
pub async fn list_imported_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_imported_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Lists the public keys of the generated BLS secret keys
pub async fn list_generated_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_generated_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Lists the public keys of the generated ETH secret keys
pub async fn list_eth_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_eth_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportRequest {
    /// The BLS keystore to import
    pub keystore: String,
    /// The encrypted keystore password
    pub ct_password_hex: String,
    /// The SECP256K1 public key safeguarded in TEE that encrypted ct_password
    pub encrypting_pk_hex: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponse {
    pub data: [KeyImportResponseInner; 1],
}

impl KeyImportResponse {
    pub fn new(pk_hex: String) -> Self {
        // prepend 0x
        let msg = match pk_hex[0..2].into() {
            "0x" => pk_hex.to_string(),
            _ => "0x".to_owned() + &pk_hex.to_string(),
        };
        let data = KeyImportResponseInner {
            status: "imported".to_string(),
            message: msg,
        };
        let resp = KeyImportResponse { data: [data] };
        resp
    }
}

/// Decrypts a BLS keystore where the password was encrypted via ECDH with an SECP256K1 key
/// safeguarded by the TEE, then saves a new keystore to enclave memory. Expects the 
/// ETH encrypting_pk_hex to be compressed (33 bytes) and hex-encoded. 
pub fn decrypt_and_save_imported_bls_key(req: &KeyImportRequest) -> Result<String> {
    println!("DEBUG: servicing req: {:?}", req);
    println!("reading eth key with pk: {}", req.encrypting_pk_hex);
    // fetch safeguarded ETH private key
    let sk = read_eth_key(&req.encrypting_pk_hex)?;

    // get plaintext password
    let ct_password_hex: String = req.ct_password_hex.strip_prefix("0x").unwrap_or(&req.ct_password_hex).into();
    let ct_password_bytes = hex::decode(&ct_password_hex)?;
    let password_bytes = decrypt(&sk.serialize(), &ct_password_bytes)?;
    let password = String::from_utf8(password_bytes).with_context(|| "non-utf8 password")?;
    println!("DEBUG: decrypted password: {}", password);

    // Decrypt the keystore using decrpyted password then save bls key to new keystore
    let pk_hex = load_then_save_keystore(&req.keystore, &password)?;

    println!("Imported BLS keystore with pk: {pk_hex}");
    Ok(pk_hex)
}

/// Decrypts and saves an incoming encrypted BLS key. Returns a `KeyImportResponse` on success.
pub async fn bls_key_import_service(
    req: KeyImportRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("log: bls_key_import_service()");
    match decrypt_and_save_imported_bls_key(&req) {
        Ok(bls_pk_hex) => {
            // The key has successfully been saved, formulate http response
            let resp = KeyImportResponse::new(bls_pk_hex);
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(
                reply::json(&resp),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}


/// Handler for BLOCK type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
pub fn handle_block_type(req: BlockRequest, bls_pk_hex: String) -> Result<BLSSignature> {
    get_block_signature(bls_pk_hex, req.fork_info, req.block)
}

/// Handler for BLOCK_V2 type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
pub fn handle_block_v2_type(req: BlockV2Request, bls_pk_hex: String) -> Result<BLSSignature> {
    get_block_v2_signature(bls_pk_hex, req.fork_info, req.beacon_block.block_header)
}

/// Handler for ATTESTATION type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#attesting
pub fn handle_attestation_type(
    req: AttestationRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_attestation_signature(bls_pk_hex, req.fork_info, req.attestation)
}

/// Handler for RANDAO_REVEAL type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#randao-reveal
pub fn handle_randao_reveal_type(
    req: RandaoRevealRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_epoch_signature(bls_pk_hex, req.fork_info, req.randao_reveal.epoch)
}

/// Handler for AGGREGATE_AND_PROOF type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#broadcast-aggregate
pub fn handle_aggregate_and_proof_type(
    req: AggregateAndProofRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_aggregate_and_proof(bls_pk_hex, req.fork_info, req.aggregate_and_proof)
}

/// Handler for AGGREGATION_SLOT type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection
pub fn handle_aggregation_slot_type(
    req: AggregationSlotRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_slot_signature(bls_pk_hex, req.fork_info, req.aggregation_slot.slot)
}

/// Handler for DEPOSIT type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#submit-deposit
// pub fn handle_deposit_type(req: DepositRequest, bls_pk_hex: String) -> Result<BLSSignature> {
pub fn handle_deposit_type(req: DepositRequest, bls_pk_hex: String) -> Result<DepositResponse> {
    println!("got deposit type");
    get_deposit_signature(bls_pk_hex, req.deposit, req.genesis_fork_version)
}

/// Handler for VOLUNTARY_EXIT type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntary-exits
pub fn handle_voluntary_exit_type(
    req: VoluntaryExitRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_voluntary_exit_signature(bls_pk_hex, req.fork_info, req.voluntary_exit)
}

/// Handler for SYNC_COMMITTEE_MESSAGE type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee-messages
pub fn handle_sync_committee_msg_type(
    req: SyncCommitteeMessageRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_sync_committee_message(bls_pk_hex, req.fork_info, req.sync_committee_message)
}

/// Handler for SYNC_COMMITTEE_SELECTION_PROOF type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection
pub fn handle_sync_committee_selection_proof_type(
    req: SyncCommitteeSelectionProofRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_sync_committee_selection_proof(
        bls_pk_hex,
        req.fork_info,
        req.sync_aggregator_selection_data,
    )
}

/// Handler for SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF type
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution
pub fn handle_sync_committee_contribution_and_proof_type(
    req: SyncCommitteeContributionAndProofRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_contribution_and_proof_signature(bls_pk_hex, req.fork_info, req.contribution_and_proof)
}

/// Handler for VALIDATOR_REGISTRATION type
/// https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#signing
pub fn handle_validator_registration_type(
    req: ValidatorRegistrationRequest,
    bls_pk_hex: String,
) -> Result<BLSSignature> {
    get_validator_registration_signature(bls_pk_hex, req.validator_registration)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecureSignerSig {
    pub signature: String
}

impl SecureSignerSig {
    pub fn new(sig: &[u8]) -> Self {
        SecureSignerSig {
            signature: format!("0x{}", hex::encode(sig))
        }
    }
}

/// Return hex-encoded signature for easy JSON response
pub fn success_response(sig: &[u8]) -> SecureSignerSig {
    SecureSignerSig::new(sig)
}

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub async fn secure_sign_bls(
    bls_pk_hex: String,
    req: bytes::Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    // strip 0x prefix if exists
    let bls_pk_hex = bls_pk_hex.strip_prefix("0x").unwrap_or(&bls_pk_hex).into();
    println!("Signing pk {:#?}", bls_pk_hex);
    println!("{:#?}", req);

    // Match over each possible datatype
    match serde_json::from_slice(&req) {
        Ok(BLSSignMsg::BLOCK(req)) | Ok(BLSSignMsg::block(req)) => {
            // handle "BLOCK" type request
            match handle_block_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 412 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert(
                        "error",
                        format!(
                            "{:?}, Signing operation failed due to slashing protection rules",
                            e
                        ),
                    );
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::PRECONDITION_FAILED,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::BLOCK_V2(req)) | Ok(BLSSignMsg::block_v2(req)) => {
            // handle "BLOCK_V2" type request
            match handle_block_v2_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 412 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert(
                        "error",
                        format!(
                            "{:?}, Signing operation failed due to slashing protection rules",
                            e
                        ),
                    );
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::PRECONDITION_FAILED,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::ATTESTATION(req)) | Ok(BLSSignMsg::attestation(req)) => {
            // handle "ATTESTATION" type request
            match handle_attestation_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 412 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert(
                        "error",
                        format!(
                            "{:?}, Signing operation failed due to slashing protection rules",
                            e
                        ),
                    );
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::PRECONDITION_FAILED,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::RANDAO_REVEAL(req)) | Ok(BLSSignMsg::randao_reveal(req)) => {
            // handle "RANDAO_REVEAL" type request
            match handle_randao_reveal_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::AGGREGATE_AND_PROOF(req)) | Ok(BLSSignMsg::aggregate_and_proof(req)) => {
            let ab = &req.aggregate_and_proof.aggregate.aggregation_bits;

            println!("agg bits: {:?}, {:?}", ab, hex::encode(ab.as_slice()));
            // handle "AGGREGATE_AND_PROOF" type request
            match handle_aggregate_and_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::AGGREGATION_SLOT(req)) | Ok(BLSSignMsg::aggregation_slot(req)) => {
            // handle "AGGREGATION_SLOT" type request
            match handle_aggregation_slot_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::DEPOSIT(req)) | Ok(BLSSignMsg::deposit(req)) => {
            // handle "DEPOSIT" type request
            match handle_deposit_type(req, bls_pk_hex) {
                Ok(resp) => {
                    println!("dr: {:?}", resp);
                    Ok(reply::with_status(
                    reply::json(&resp),
                    StatusCode::OK))
            },
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::VOLUNTARY_EXIT(req)) | Ok(BLSSignMsg::voluntary_exit(req)) => {
            // handle "VOLUNTARY_EXIT" type request
            match handle_voluntary_exit_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::SYNC_COMMITTEE_MESSAGE(req)) | Ok(BLSSignMsg::sync_committee_message(req)) => {
            // handle "SYNC_COMMITTEE_MESSAGE" type request
            match handle_sync_committee_msg_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::SYNC_COMMITTEE_SELECTION_PROOF(req)) | Ok(BLSSignMsg::sync_committee_selection_proof(req)) => {
            // handle "SYNC_COMMITTEE_SELECTION_PROOF" type request
            match handle_sync_committee_selection_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(req)) | Ok(BLSSignMsg::sync_committee_contribution_and_proof(req)) => {
            // handle "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" type request
            match handle_sync_committee_contribution_and_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Ok(BLSSignMsg::VALIDATOR_REGISTRATION(req)) | Ok(BLSSignMsg::validator_registration(req)) => {
            // handle "VALIDATOR_REGISTRATION" type request
            match handle_validator_registration_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json::<SecureSignerSig>(&success_response(&sig)),
                    StatusCode::OK,
                )),
                // return 500 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}", e));
                    Ok(reply::with_status(
                        reply::json(&resp),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        }
        Err(e) => {
            println!("LOG - catchall error");
            // catchall error if the request is not valid
            let mut resp = HashMap::new();
            resp.insert("error", format!("Type not in ['BLOCK', 'ATTESTATION', RANDAO_REVEAL', 'AGGREGATION_SLOT', 'AGGREGATE_AND_PROOF', 'DEPOSIT','VOLUNTARY_EXIT', 'SYNC_COMMITEE_MESSAGE', 'SYNC_COMMITEE_SELECTION_PROOF', 'SYNC_COMMITEE_CONTRIBUTION_AND_PROOF' 'VALIDATOR_REGISTRATION'], {:?}", e));
            Ok(reply::with_status(
                reply::json(&resp),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}



#[cfg(test)]
pub mod mock_requests {
    pub fn mock_attestation_request(src_epoch: &str, tgt_epoch: &str) -> String {
        let req = format!(r#"
        {{
            "type": "ATTESTATION",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x00000001",
                   "current_version":"0x00000001",
                   "epoch":"0"
                }},
                "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }},
            "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
            "attestation": {{
                "slot": "255",
                "index": "65535",
                "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                "source": {{
                    "epoch": "{src_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }},
                "target": {{
                    "epoch": "{tgt_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }}
            }}
        }}"#);
        // println!("{req}");
        req
    }

    pub fn mock_propose_block_request(slot: &str) -> String {
        let req = format!(r#"
            {{
               "type":"BLOCK",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x00000001",
                     "current_version":"0x00000001",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "block":{{
                  "slot":"{slot}",
                  "proposer_index":"5",
                  "parent_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
                  "state_root":"0x2b530d6262576277f1cc0dbe341fd919f9f8c5c92fc9140dff6db4ef34edea0d",
                  "body":{{
                     "randao_reveal":"0xa686652aed2617da83adebb8a0eceea24bb0d2ccec9cd691a902087f90db16aa5c7b03172a35e874e07e3b60c5b2435c0586b72b08dfe5aee0ed6e5a2922b956aa88ad0235b36dfaa4d2255dfeb7bed60578d982061a72c7549becab19b3c12f",
                     "eth1_data":{{
                        "deposit_root":"0x6a0f9d6cb0868daa22c365563bb113b05f7568ef9ee65fdfeb49a319eaf708cf",
                        "deposit_count":"8",
                        "block_hash":"0x4242424242424242424242424242424242424242424242424242424242424242"
                     }},
                     "graffiti":"0x74656b752f76302e31322e31302d6465762d6338316361363235000000000000",
                     "proposer_slashings":[],
                     "attester_slashings":[],
                     "attestations":[],
                     "deposits":[],
                     "voluntary_exits":[]
                  }}
               }},
               "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }}"#);
        req
    }

    pub fn mock_randao_reveal_request() -> String {
        let req = format!(r#"
            {{
               "type":"randao_reveal",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x00000000",
                     "current_version":"0x00000000",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
               }},
               "signingRoot": "0xbf70dbbbc83299fb877334eaeaefb32df44242c1bf078cdc1836dcc3282d4fbd",
               "randao_reveal":{{
                    "epoch": "0"
               }}
            }}"#);
        // println!("{req}");
        req
    }

    pub fn mock_aggregate_and_proof_request(src_epoch: &str, tgt_epoch: &str) -> String {
        let type_: String = "AGGREGATE_AND_PROOF".into();
        // let aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE> = BitList::with_capacity(2048).unwrap();

        let req = format!(r#"
            {{
               "type":"{type_}",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x00000001",
                     "current_version":"0x00000001",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
               "aggregate_and_proof":{{
                    "aggregator_index": "5",
                    "aggregate": {{
                        "aggregation_bits": "0x1234",
                        "data": {{
                            "slot": "750",
                            "index": "1",
                            "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                            "source": {{
                                "epoch": "{src_epoch}",
                                "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                            }},
                            "target": {{
                                "epoch": "{tgt_epoch}",
                                "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                            }}
                        }},
                        "signature": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                    }},
                    "selection_proof": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }}
            }}"#);
        req
    }

    pub fn mock_block_v2_bellatrix_request(slot: &str) -> String {
        let req = format!(r#"
        {{
            "type": "BLOCK_V2",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x80000070",
                   "current_version":"0x80000071",
                   "epoch":"750"
                }},
                "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
             }},
             "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
            "beacon_block": {{
                "version": "BELLATRIX",
                "block_header": {{
                    "slot": "{slot}",
                    "proposer_index": "0",
                    "parent_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    "state_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body_root":"0xcd7c49966ebe72b1214e6d4733adf6bf06935c5fbc3b3ad08e84e3085428b82f"
                }}
            }}
        }}"#);
        req
    }


    pub fn mock_validator_registration_request() -> String {
        let req = format!(r#"
        {{
            "type": "VALIDATOR_REGISTRATION",
            "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
            "validator_registration": {{
                "fee_recipient": "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "gas_limit": "30000000",
                "timestamp":"100",
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18"
            }}
        }}"#);
        req
    }


    pub fn mock_deposit_request() -> String {
        let req = format!(r#"
        {{
            "type": "DEPOSIT",
            "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
            "deposit": {{
                "pubkey": "0x8996c1117cb75927eb53db74b25c3668c0f7b08d34cdb8de1062bef578fb1c1e32032e0555e9f5be47cd5e8f0f2705d5",
                "withdrawal_credentials": "0x75362a41a82133d71eee01e602ad564c73590557bb7c994cf9be5620d2023a58",
                "amount":"32000000000"
            }}
        }}"#);
        req
    }


    pub fn mock_aggregation_slot_request() -> String {
        unimplemented!()
    }

    pub fn mock_sync_committee_message_request() -> String {
        unimplemented!()
    }

    pub fn mock_sync_committee_selection_proof_request() -> String {
        unimplemented!()
    }

    pub fn mock_sync_committee_contribution_and_proof_request() -> String {
        unimplemented!()
    }


}