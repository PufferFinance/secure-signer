use crate::keys::{bls_key_gen, eth_key_gen, read_eth_key, write_key, list_eth_keys, list_imported_bls_keys, list_generated_bls_keys, bls_sign};
use crate::attest::{epid_remote_attestation, AttestationEvidence};
use crate::beacon::*;

use anyhow::{Result, bail};
use blst::min_pk::SecretKey;
use serde::{Deserialize, Serialize};
use warp::{reply, http::StatusCode};
use ecies::decrypt;
use std::collections::HashMap;
use bytes::{Buf, Bytes};

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn epid_remote_attestation_service(req: AttestationRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let from_file = true;
    match epid_remote_attestation(&req.pub_key, from_file) {
        Ok(evidence) => {
            // TODO can embed AttestationEvidence into parent data structure
            Ok(reply::with_status(reply::json(&evidence), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    pub pub_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyProvisionRequest {
    pub eth_pk_hex: String,
    pub evidence: AttestationEvidence,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyProvisionResponse {
    pub ct_bls_sk_hex: String,
    pub bls_pk_hex: String,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys.iter().map(|pk| {
            // Strip leading 0x if included
            let pubkey = match pk[0..2].into() {
                "0x" => pk[2..].to_string(),
                _ => pk.to_string(),
            };
            ListKeysResponseInner {
                pubkey: pubkey.into()
            }
        }).collect();

        ListKeysResponse {
            data: inners
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyGenResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyGenResponse {
    pub data: [KeyGenResponseInner; 1],
}

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn bls_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    let save_key = true;
    match bls_key_gen(save_key) {
        Ok(pk) => {
            let pk_hex = hex::encode(pk.compress());
            let data = KeyGenResponseInner { status: "generated".to_string(), message: pk_hex};
            let resp = KeyGenResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// Runs all the logic to generate and save a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn eth_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    match eth_key_gen() {
        Ok(pk) => {
            let pk_hex = hex::encode(pk.serialize());
            let data = KeyGenResponseInner { status: "generated".to_string(), message: pk_hex};
            let resp = KeyGenResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_imported_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_imported_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_generated_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_generated_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_eth_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_eth_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct BlsSignRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    pub signing_root: String,
    pub msg_hex: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlsSignResponse {
    pub msg_hex: String,
    pub bls_sig_hex: String,
}

/// Handler for secure_sign_block()
// pub async fn handle_block_type(req: ProposeBlockRequest, bls_pk_hex: String) -> Result<impl warp::Reply, warp::Rejection> {
//     if req.type_ != "BLOCK" {
//         let mut resp = HashMap::new();
//         resp.insert("error", "Bad request format");
//         return Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST));
//     }

//     let domain = compute_domain(
//         DOMAIN_BEACON_PROPOSER, 
//         Some(req.fork_info.fork.current_version),
//         Some(req.fork_info.genesis_validators_root)
//     );

//     match secure_sign_block(bls_pk_hex, req.block, domain) {
//         Ok(sig) => {
//             // TODOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
//             let mut resp = HashMap::new();
//             resp.insert("error, no ", "UNIMPLEMENTED");
//             Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
//         },
//         // return 412 error
//         Err(e) => {
//             let mut resp = HashMap::new();
//             resp.insert("error", "Signing operation failed due to slashing protection rules");
//             Ok(reply::with_status(reply::json(&resp), StatusCode::PRECONDITION_FAILED))
//         }
//     }
// }

// /// Handler for secure_sign_attestation()
// pub async fn handle_attestation_type(req: AttestBlockRequest, bls_pk_hex: String) -> Result<impl warp::Reply, warp::Rejection> {
//     if req.type_ != "ATTESTATION" {
//         let mut resp = HashMap::new();
//         resp.insert("error", "Bad request format");
//         return Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST));
//     }

//     let mut resp = HashMap::new();
//     resp.insert("error, no ", "asdfasf");
//     Ok(reply::with_status(reply::json(&resp), StatusCode::OK))

//     // match secure_sign_block() {

//     // }
// }

// /// Handler for secure_sign_randao()
// pub async fn handle_randao_reveal_type(req: RandaoRevealRequest, bls_pk_hex: String) -> Result<impl warp::Reply, warp::Rejection> {
//     if req.type_ != "RANDAO_REVEAL" {
//         let mut resp = HashMap::new();
//         resp.insert("error", "Bad request format");
//         return Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST));
//     }

//     let mut resp = HashMap::new();
//     resp.insert("error, no ", "asdfasf");
//     Ok(reply::with_status(reply::json(&resp), StatusCode::OK))

//     // match secure_sign_block() {

//     // }
// }

/// maintain compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing 
// pub async fn secure_sign_bls(identifier: String, req: bytes::Bytes) -> Result<impl warp::Reply, warp::Rejection> {
//     match serde_json::from_slice::<ProposeBlockRequest>(&req) {
//         Ok(req) => {
//             // handle "BLOCK" type request
//             handle_block_type(req, identifier)
//         },
//         Err(e) => {
//             match serde_json::from_slice::<AttestBlockRequest>(&req) {
//                 Ok(req) => {
//                     // handle "ATTESTATION" type request
//                     handle_attestation_type(req, identifier)
//                 },
//                 Err(e) => {
//                     match serde_json::from_slice::<RandaoRevealRequest>(&req) {
//                         Ok(req) => {
//                             // handle "RANDAO_REVEAL" type request
//                             handle_randao_reveal_type(req, identifier)
//                         },
//                         Err(e) => {
//                             let mut resp = HashMap::new();
//                             resp.insert("error", "Type not in ['BLOCK', 'ATTESTATION', RANDAO_REVEAL']");
//                             Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST))
//                         }
//                     }
//                 }
//             }
//         }
//     }
// }

/// Handler for secure_sign_block()
pub fn handle_block_type(req: ProposeBlockRequest, bls_pk_hex: String) -> Result<BLSSignature> {
    if req.type_ != "BLOCK" {
        bail!("Bad request format");
    }

    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER, 
        Some(req.fork_info.fork.current_version),
        Some(req.fork_info.genesis_validators_root)
    );

    secure_sign_block(bls_pk_hex, req.block, domain)
}

/// Handler for secure_sign_attestation()
pub fn handle_attestation_type(req: AttestBlockRequest, bls_pk_hex: String) -> Result<BLSSignature> {
    if req.type_ != "ATTESTATION" {
        bail!("Bad request format");
    }

    let domain = compute_domain(
        DOMAIN_BEACON_ATTESTER, 
        Some(req.fork_info.fork.current_version),
        Some(req.fork_info.genesis_validators_root)
    );

    secure_sign_attestation(bls_pk_hex, req.attestation, domain)
}

/// Handler for secure_sign_randao()
pub fn handle_randao_reveal_type(req: RandaoRevealRequest, bls_pk_hex: String) -> Result<BLSSignature> {
    if req.type_ != "RANDAO_REVEAL" {
        bail!("Bad request format");
    }

    let domain = compute_domain(
        DOMAIN_RANDAO, 
        Some(req.fork_info.fork.current_version),
        Some(req.fork_info.genesis_validators_root)
    );

    secure_sign_randao(bls_pk_hex, req.randao_reveal, domain)
}

pub async fn secure_sign_bls(identifier: String, req: bytes::Bytes) -> Result<impl warp::Reply, warp::Rejection> {
    match serde_json::from_slice::<ProposeBlockRequest>(&req) {
        Ok(req) => {
            // handle "BLOCK" type request
            match handle_block_type(req, identifier) {
                Ok(sig) => {
                    let mut resp = HashMap::new();
                    resp.insert("signature", hex::encode(&sig[..]));
                    Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
                },
                // return 412 error
                Err(e) => {
                    let mut resp = HashMap::new();
                    resp.insert("error", format!("{:?}, Signing operation failed due to slashing protection rules", e));
                    Ok(reply::with_status(reply::json(&resp), StatusCode::PRECONDITION_FAILED))
                }
            }
        },
        Err(e) => {
            match serde_json::from_slice::<AttestBlockRequest>(&req) {
                Ok(req) => {
                    // handle "ATTESTATION" type request
                    match handle_attestation_type(req, identifier) {
                        Ok(sig) => {
                            let mut resp = HashMap::new();
                            resp.insert("signature", hex::encode(&sig[..]));
                            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
                        },
                        // return 412 error
                        Err(e) => {
                            let mut resp = HashMap::new();
                            resp.insert("error", format!("{:?}, Signing operation failed due to slashing protection rules", e));
                            Ok(reply::with_status(reply::json(&resp), StatusCode::PRECONDITION_FAILED))
                        }
                    }
                },
                Err(e) => {
                    match serde_json::from_slice::<RandaoRevealRequest>(&req) {
                        Ok(req) => {
                            // handle "RANDAO_REVEAL" type request
                            match handle_randao_reveal_type(req, identifier) {
                                Ok(sig) => {
                                    let mut resp = HashMap::new();
                                    resp.insert("signature", hex::encode(&sig[..]));
                                    Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
                                },
                                // return 412 error
                                Err(e) => {
                                    let mut resp = HashMap::new();
                                    resp.insert("error", format!("{:?}, Signing operation failed due to slashing protection rules", e));
                                    Ok(reply::with_status(reply::json(&resp), StatusCode::PRECONDITION_FAILED))
                                }
                            }
                        },
                        Err(e) => {
                            // catchall error if signing type not one of ['BLOCK', 'ATTESTATION', RANDAO_REVEAL']
                            let mut resp = HashMap::new();
                            resp.insert("error", "Type not in ['BLOCK', 'ATTESTATION', RANDAO_REVEAL']");
                            Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST))
                        }
                    }
                }
            }
        }
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportRequest {
    pub ct_bls_sk_hex: String,
    pub bls_pk_hex: String,
    /// The SECP256K1 public key (hex) safeguarded in TEE
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

pub fn decrypt_and_save_imported_bls_key(req: &KeyImportRequest) -> Result<()> {
    println!("DEBUG: servicing req: {:?}", req);
    println!("reading eth key with pk: {}", req.encrypting_pk_hex);
    let sk = read_eth_key(&req.encrypting_pk_hex)?;
    let ct_bls_sk_bytes = hex::decode(&req.ct_bls_sk_hex)?;
    let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk_bytes)?;
    let bls_sk = match SecretKey::from_bytes(&bls_sk_bytes) {
        Ok(sk) => sk,
        Err(e) => bail!("decrypt_and_save_imported_bls_key() couldn't recover bls sk from import request: {:?}", e),
    };
    if hex::encode(bls_sk.sk_to_pk().serialize()) != req.bls_pk_hex {
        bail!("The imported bls sk doesn't match the expected bls pk")
    }
    let fname = format!("bls_keys/imported/{}", req.bls_pk_hex);
    let bls_sk_hex = hex::encode(bls_sk.serialize());
    // save the bls key  
    write_key(&fname, &bls_sk_hex)
}

/// Decrypts and saves an incoming encrypted BLS key. Returns a `KeyImportResponse` on success.
pub async fn bls_key_import_service(req: KeyImportRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match decrypt_and_save_imported_bls_key(&req) {
        Ok(()) => {
            // The key has successfully been saved, formulate http response
            let data = KeyImportResponseInner { status: "imported".to_string(), message: req.bls_pk_hex};
            let resp = KeyImportResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}
