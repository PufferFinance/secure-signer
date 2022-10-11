use serde_derive::{Deserialize, Serialize};
use warp::{Filter, http::Response};
use blst::min_pk::{SecretKey, PublicKey, Signature, AggregatePublicKey, AggregateSignature};
use blst::BLST_ERROR;
use std::path::PathBuf;
use std::fs;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub const CIPHER_SUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn new_bls_key() -> SecretKey {
    // rng
    let mut rng = ChaCha20Rng::from_entropy();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    // key gen
    SecretKey::key_gen(&ikm, &[]).expect("Unable to generate SecretKey")
}

pub fn bls_key_gen() -> PublicKey {
    let sk = new_bls_key();
    let pk = sk.sk_to_pk();

    // compress pk to 48B
    let pk_hex: String = hex::encode(pk.compress());
    let sk_hex: String = hex::encode(sk.to_bytes());

    assert!(pk.to_bytes() == pk.compress());

    // save secret key using pk_hex as file identifier (omitting '0x' prefix)
    assert!(write_key(&pk_hex, &sk_hex).is_ok());

    pk
}

pub fn verify_bls_sig(sig: Signature, pk: PublicKey, msg: &[u8]) -> bool {
    let err = sig.verify(
        true, // sig_groupcheck
        msg, // msg
        CIPHER_SUITE, // dst
        &[], // aug
        &pk, // pk
        false); // pk_validate 

    err == BLST_ERROR::BLST_SUCCESS
}

fn bls_sign(pk_hex: &String, msg: &[u8]) -> Signature {
    // read pk
    let pk_bytes = hex::decode(pk_hex).expect("bad pk hex string");
    let pk = PublicKey::from_bytes(&pk_bytes).expect("bad pk bytes");

    // read sk
    let sk = read_key(&pk_hex).expect("Unable to read key");

    // valid keypair
    assert!(sk.sk_to_pk() == pk);
    println!("sk recovered {:?}", sk);

    // sign the message
    let sig = sk.sign(msg, CIPHER_SUITE, &[]);

    // verify the signatures correctness
    assert!(verify_bls_sig(sig, pk, msg));

    // Return the BLS signature
    sig
}

pub fn write_key(pk_hex: &String, sk_hex: &String) -> std::io::Result<()> {
    let file_path: PathBuf = ["./etc/keys/", pk_hex.as_str()].iter().collect();
    if let Some(p) = file_path.parent() { 
        fs::create_dir_all(p)?
    }; 
    fs::write(&file_path, sk_hex)
}

pub fn read_key(pk_hex: &String) -> Result<SecretKey, BLST_ERROR> {
    let file_path: PathBuf = ["./etc/keys/", pk_hex.as_str()].iter().collect();
    let sk_rec_bytes = fs::read(&file_path).expect("Unable to read key");
    let sk_rec_dec = hex::decode(sk_rec_bytes).expect("Unable to decode hex");
    SecretKey::from_bytes(&sk_rec_dec)
}

/// todo error handling
pub fn list_keys() -> Vec<String> {
    let paths = fs::read_dir("./etc/keys/").expect("No keys saved");
    paths.map(|path| {
        let p = path.unwrap().path();
        let pk_hex = p.file_name().unwrap();
        pk_hex.to_os_string().into_string().unwrap()
    }).collect()
}



#[derive(Deserialize, Serialize)]
pub struct KeyGenResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize)]
pub struct KeyGenResponse {
    pub data: [KeyGenResponseInner; 1],
}

pub fn key_gen_service() -> KeyGenResponse {
    let pk = bls_key_gen();
    let pk_hex = hex::encode(pk.compress());
    let data = KeyGenResponseInner { status: "imported".to_string(), message: pk_hex};
    KeyGenResponse { data: [data] }
}

/// Generates a new BLS private key in Enclave. To remain compatible with web3signer POST /eth/v1/keystores, the JSON body is not parsed. The BLS public key is returned 
pub fn key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let key_gen = warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .map(|| {
            let resp = key_gen_service();
            warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::OK)

            // todo add unhappy cases
    });
    key_gen
}


#[derive(Deserialize, Serialize)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys.iter().map(|pk| {
            ListKeysResponseInner {
                pubkey: format!("0x{}", pk),
            }
        }).collect();

        ListKeysResponse {
            data: inners
        }
    }
}

/// Returns the hex-encoded BLS public keys that have their corresponding secret keys safeguarded in Enclave memory. 
pub fn list_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let key_gen = warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .map(|| {
            let pks = list_keys();
            let resp = ListKeysResponse::new(pks);
            warp::reply::with_status(warp::reply::json(&resp), warp::http::StatusCode::OK)

            // todo add unhappy cases

            // todo add derivation_path
    });
    key_gen
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn bls_key_gen_produces_valid_keys_and_sig() {
        let pk: PublicKey = bls_key_gen();
        let pk_hex = hex::encode(pk.compress());
        let msg = b"yadayada";
        let sig = bls_sign(&pk_hex, msg);
        assert!(verify_bls_sig(sig, pk, msg));
    }

    #[test]
    fn test_aggregate() {
        // number of nodes
        const n: usize = 10;

        // n identical msgs
        let msgs = vec![b"yadayada"; n];
        let msgs_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();

        // generate n sks
        let sks: Vec<SecretKey> = (0..n).map(|_| {
            let sk = new_bls_key();
            println!("sk: {:?}", hex::encode(sk.to_bytes()));
            sk
        }).collect();

        // derive n pks
        let pks: Vec<PublicKey> = sks.iter().map(|sk| {
            let pk = sk.sk_to_pk();
            println!("pk: {:?}", hex::encode(pk.to_bytes()));
            pk
        }).collect();
        let pks_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk) .collect();

        // each node signs identical msg
        let sigs: Vec<Signature> = sks
            .iter()
            .zip(msgs.clone().into_iter())
            .map(|(sk, msg)| {
            let sig = sk.sign(msg.as_slice(), CIPHER_SUITE, &[]);
            println!("sig: {:?}", hex::encode(sig.to_bytes()));
            sig
        }).collect();
        let sigs_refs = sigs.iter().map(|s| s).collect::<Vec<&Signature>>();

        // verify signatures
        let errs = sigs
            .iter()
            .zip(msgs.into_iter())
            .zip(pks.iter())
            .map(|((s, m), pk)| (s.verify(true, m, CIPHER_SUITE, &[], pk, true)))
            .collect::<Vec<BLST_ERROR>>();
                assert_eq!(errs, vec![BLST_ERROR::BLST_SUCCESS; n]);

        // aggregate the n BLS public keys into 1 aggregate pk
        let agg_pk = match AggregatePublicKey::aggregate(&pks_refs, true) {
            Ok(agg) => agg,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };
        println!("agg_pk: {:?}", hex::encode(agg_pk.to_public_key().to_bytes()));
        
        // aggregate the n signatures into 1 
        let agg = match AggregateSignature::aggregate(&sigs_refs, true) {
            Ok(agg) => agg,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        let agg_sig = agg.to_signature();
        println!("agg_sig: {:?}", hex::encode(agg_sig.to_bytes()));

        // verify the aggregate sig using aggregate_verify
        let mut result = agg_sig
            .aggregate_verify(false, &msgs_refs, CIPHER_SUITE, &pks_refs, false);
        assert_eq!(result, BLST_ERROR::BLST_SUCCESS);

        // verify the aggregate signature using the aggregate pk
        result = agg_sig.verify(false, msgs_refs[0], CIPHER_SUITE, &[], &agg_pk.to_public_key(), false);
        assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
    }
}