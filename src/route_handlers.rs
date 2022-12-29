use crate::eth_signing::*;
use crate::eth_types::*;
use crate::keys::{
    bls_key_gen, eth_key_gen, list_eth_keys, list_generated_bls_keys,
    list_imported_bls_keys, read_eth_key, write_key,
};
use crate::remote_attesation::{epid_remote_attestation, AttestationEvidence};

use anyhow::{bail, Result};
use blst::min_pk::SecretKey;
use ecies::decrypt;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use std::collections::HashMap;
use warp::{http::StatusCode, reply};

#[derive(Deserialize, Serialize, Debug)]
pub struct RemoteAttestationRequest {
    pub pub_key: String,
}

//todo
/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn epid_remote_attestation_service(
    req: RemoteAttestationRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    let from_file = true;
    match epid_remote_attestation(&req.pub_key, from_file) {
        Ok(evidence) => {
            // TODO can embed AttestationEvidence into parent data structure
            Ok(reply::with_status(reply::json(&evidence), StatusCode::OK))
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
                // Strip leading 0x if included
                let pubkey = match pk[0..2].into() {
                    "0x" => pk[2..].to_string(),
                    _ => pk.to_string(),
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
    let save_key = true;
    match bls_key_gen(save_key) {
        Ok(pk) => {
            let mut resp = HashMap::new();
            resp.insert("bls_pk_hex", format!("0x{}", hex::encode(pk.compress())));
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

/// Runs all the logic to generate and save a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn eth_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    match eth_key_gen() {
        Ok(pk) => {
            let mut resp = HashMap::new();
            resp.insert("eth_pk_hex", format!("0x{}", hex::encode(pk.serialize())));
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
    /// The encrypted BLS key to import
    pub ct_bls_sk_hex: String,
    /// The public key
    pub bls_pk_hex: String,
    /// The SECP256K1 public key safeguarded in TEE that encrypted ct_bls_sk_hex
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

/// Decrypts a BLS private key that was encrypted via ECDH with an SECP256K1 key
/// safeguarded by the TEE, then saves the BLS key.
pub fn decrypt_and_save_imported_bls_key(req: &KeyImportRequest) -> Result<()> {
    println!("DEBUG: servicing req: {:?}", req);
    println!("reading eth key with pk: {}", req.encrypting_pk_hex);
    // fetch safeguarded ETH private key
    let sk = read_eth_key(&req.encrypting_pk_hex)?;

    // get plaintext bls key
    let ct_bls_sk_bytes = hex::decode(&req.ct_bls_sk_hex)?;
    let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk_bytes)?;
    let bls_sk = match SecretKey::from_bytes(&bls_sk_bytes) {
        Ok(sk) => sk,
        Err(e) => bail!(
            "decrypt_and_save_imported_bls_key() couldn't recover bls sk from import request: {:?}",
            e
        ),
    };

    // verify supplied pk is dervied from this sk
    if hex::encode(bls_sk.sk_to_pk().serialize()) != req.bls_pk_hex {
        bail!("The imported bls sk doesn't match the expected bls pk")
    }

    // save the bls key
    let fname = format!("bls_keys/imported/{}", req.bls_pk_hex);
    let bls_sk_hex = hex::encode(bls_sk.serialize());
    write_key(&fname, &bls_sk_hex)
}

/// Decrypts and saves an incoming encrypted BLS key. Returns a `KeyImportResponse` on success.
pub async fn bls_key_import_service(
    req: KeyImportRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    match decrypt_and_save_imported_bls_key(&req) {
        Ok(()) => {
            // The key has successfully been saved, formulate http response
            let data = KeyImportResponseInner {
                status: "imported".to_string(),
                message: req.bls_pk_hex,
            };
            let resp = KeyImportResponse { data: [data] };
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

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockV2Request {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub beacon_block: BlockV2RequestWrapper,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockV2RequestWrapper {
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub attestation: AttestationData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RandaoRevealRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub randao_reveal: RandaoReveal,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AggregateAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub aggregate_and_proof: AggregateAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AggregationSlotRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub aggregation_slot: AggregationSlot,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DepositRequest {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub deposit: DepositData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VoluntaryExitRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub voluntary_exit: VoluntaryExit,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeMessageRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub sync_committee_message: SyncCommitteeMessage,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeSelectionProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub sync_aggregator_selection_data: SyncAggregatorSelectionData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeContributionAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub contribution_and_proof: ContributionAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ValidatorRegistrationRequest {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub validator_registration: ValidatorRegistration,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum BLSSignMsg {
    BLOCK(BlockRequest),
    BLOCK_V2(BlockV2Request),
    ATTESTATION(AttestationRequest),
    RANDAO_REVEAL(RandaoRevealRequest),
    AGGREGATE_AND_PROOF(AggregateAndProofRequest),
    AGGREGATION_SLOT(AggregationSlotRequest),
    DEPOSIT(DepositRequest),
    VOLUNTARY_EXIT(VoluntaryExitRequest),
    SYNC_COMMITTEE_MESSAGE(SyncCommitteeMessageRequest),
    SYNC_COMMITTEE_SELECTION_PROOF(SyncCommitteeSelectionProofRequest),
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(SyncCommitteeContributionAndProofRequest),
    VALIDATOR_REGISTRATION(ValidatorRegistrationRequest),
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
pub fn handle_deposit_type(req: DepositRequest, bls_pk_hex: String) -> Result<BLSSignature> {
    get_deposit_signature(bls_pk_hex, req.deposit)
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

/// Return hex-encoded signature for easy JSON response
pub fn success_response(sig: &[u8]) -> HashMap<&str, String> {
    let mut resp = HashMap::new();
    resp.insert("signature", format!("0x{}", hex::encode(sig)));
    resp
}

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub async fn secure_sign_bls(
    bls_pk_hex: String,
    req: bytes::Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    // strip 0x prefix if exists
    let bls_pk_hex = bls_pk_hex.strip_prefix("0x").unwrap_or(&bls_pk_hex).into();
    println!("{:?}", req);

    // Match over each possible datatype
    match serde_json::from_slice(&req) {
        Ok(BLSSignMsg::BLOCK(req)) => {
            // handle "BLOCK" type request
            match handle_block_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::BLOCK_V2(req)) => {
            // handle "BLOCK_V2" type request
            match handle_block_v2_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::ATTESTATION(req)) => {
            // handle "ATTESTATION" type request
            match handle_attestation_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::RANDAO_REVEAL(req)) => {
            // handle "RANDAO_REVEAL" type request
            match handle_randao_reveal_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::AGGREGATE_AND_PROOF(req)) => {
            let ab = &req.aggregate_and_proof.aggregate.aggregation_bits;

            println!("agg bits: {:?}, {:?}", ab, hex::encode(ab.as_slice()));
            // handle "AGGREGATE_AND_PROOF" type request
            match handle_aggregate_and_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::AGGREGATION_SLOT(req)) => {
            // handle "AGGREGATION_SLOT" type request
            match handle_aggregation_slot_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::DEPOSIT(req)) => {
            // handle "DEPOSIT" type request
            match handle_deposit_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::VOLUNTARY_EXIT(req)) => {
            // handle "VOLUNTARY_EXIT" type request
            match handle_voluntary_exit_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::SYNC_COMMITTEE_MESSAGE(req)) => {
            // handle "SYNC_COMMITTEE_MESSAGE" type request
            match handle_sync_committee_msg_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::SYNC_COMMITTEE_SELECTION_PROOF(req)) => {
            // handle "SYNC_COMMITTEE_SELECTION_PROOF" type request
            match handle_sync_committee_selection_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(req)) => {
            // handle "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" type request
            match handle_sync_committee_contribution_and_proof_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
        Ok(BLSSignMsg::VALIDATOR_REGISTRATION(req)) => {
            // handle "VALIDATOR_REGISTRATION" type request
            match handle_validator_registration_type(req, bls_pk_hex) {
                Ok(sig) => Ok(reply::with_status(
                    reply::json(&success_response(&sig)),
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
