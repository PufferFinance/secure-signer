use anyhow::{bail, Context, Result};

use blst::min_pk::{AggregatePublicKey, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use ecies::PublicKey as EthPublicKey;
use ecies::SecretKey as EthSecretKey;
use ecies::{decrypt, encrypt, utils::generate_keypair};
use eth_keystore::{encrypt_key, decrypt_key};
use rand::RngCore;
use sha3::{Digest, Keccak256};

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#bls-signatures
pub const CIPHER_SUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Generates Eth secret and public key, then saves the key using the
/// ETH address derived from the public key as the filename.
pub fn eth_key_gen() -> Result<EthPublicKey> {
    let (sk, pk) = new_eth_key()?;
    save_eth_key(sk, pk).with_context(|| "Failed to save generated ETH key")
}

/// Wrapper around ecies utility function to generate SECP256K1 keypair
pub fn new_eth_key() -> Result<(EthSecretKey, EthPublicKey)> {
    Ok(generate_keypair())
}

pub fn eth_sk_to_hex(sk: &EthSecretKey) -> String {
    hex::encode(sk.serialize())
}

/// Converts SECP256K1 key to compressed 33 bytes
pub fn eth_pk_to_hex(pk: &EthPublicKey) -> String {
    hex::encode(pk.serialize_compressed())
}

pub fn eth_pk_from_hex(pk_hex: String) -> Result<EthPublicKey> {
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    let pk_bytes = hex::decode(&pk_hex)?;
    let mut pk_compressed_bytes = [0_u8; 33];
    pk_compressed_bytes.clone_from_slice(&pk_bytes);

    match EthPublicKey::parse_compressed(&pk_compressed_bytes) {
        Ok(pk) => Ok(pk),
        Err(e) => bail!(
            "failed to recover ETH pk from pk_hex: {}, error: {:?}",
            pk_hex,
            e
        ),
    }
}

/// keccak hash function to hash arbitrary bytes to 32 bytes
pub fn keccak(bytes: &[u8]) -> Result<[u8; 32]> {
    // create a Keccak256 object
    let mut hasher = Keccak256::new();

    // write input message
    hasher.update(bytes);

    // read hash digest
    let digest: [u8; 32] = hasher
        .finalize()
        .as_slice()
        .try_into()
        .with_context(|| "keccak could not be cast to [u8; 32,]")?;

    Ok(digest)
}

/// Converts an Eth pbulic key to a wallet address, encoded as hex string
pub fn pk_to_eth_addr(pk: &EthPublicKey) -> Result<String> {
    // get the uncompressed PK in bytes (should be 65)
    let pk_bytes = pk.serialize();

    if pk_bytes.len() != 65 {
        bail!("SECP256K1 pub key must be 65B, len was: {}", pk_bytes.len());
    }

    // hash of PK bytes (skip the 1st byte)
    let digest: [u8; 32] =
        keccak(&pk_bytes[1..]).with_context(|| "keccak failed when converting pk to eth addr")?;

    // keep the last 20 bytes
    let last = &digest[12..];

    // encode the bytes as a hex string
    let hex_str = hex::encode(last);

    // Convert to eth checksum address
    checksum(hex_str.as_str())
}

// Adapted from: https://github.com/miguelmota/rust-eth-checksum/
pub fn checksum(address: &str) -> Result<String> {
    let address = address.trim_start_matches("0x").to_lowercase();

    let hash_bytes = keccak(address.as_bytes())?;
    let address_hash_string = hex::encode(&hash_bytes);
    let address_hash = address_hash_string.as_str();

    Ok(address
        .char_indices()
        .fold(String::from("0x"), |mut acc, (index, address_char)| {
            // this cannot fail since it's Keccak256 hashed
            let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

            if n > 7 {
                // make char uppercase if ith character is 9..f
                acc.push_str(&address_char.to_uppercase().to_string())
            } else {
                // already lowercased
                acc.push(address_char)
            }

            acc
        }))
}

/// write the Eth SECP256K1 secret key to a secure file using the hex encoded pk as filename
fn save_eth_key(sk: EthSecretKey, pk: EthPublicKey) -> Result<EthPublicKey> {
    let pk_hex = eth_pk_to_hex(&pk);
    println!("new enclave pk: 0x{}", pk_hex);

    let sk_hex = eth_sk_to_hex(&sk);

    write_key(&format!("eth_keys/{}", pk_hex), &sk_hex).with_context(|| "eth sk failed to save")?;

    Ok(pk)
}

pub fn new_keystore(p: &Path, password: &str, name: &str, sk_bytes: &[u8]) -> Result<String> {
    fs::create_dir_all(p).with_context(|| "Failed to create dir for keystore")?;
    let mut rng = rand::thread_rng();
    // Generates a new Scrypt keystore
    let name = encrypt_key(
        p,
        &mut rng,
        sk_bytes,
        password,
        Some(name))?;
    Ok(name)
}

pub fn load_keystore(keystore_path: String, keystore_password: String) -> Result<(String, String)> {
    let sk_bytes = decrypt_key(Path::new(&keystore_path), &keystore_password)?;
    let pk = bls_sk_from_hex(hex::encode(&sk_bytes))?.sk_to_pk();

    let sk_hex = "0x".to_string() + &hex::encode(&sk_bytes);
    let pk_hex = "0x".to_string() + &hex::encode(pk.compress());
    println!(
        "DEBUG loaded keystore: public key: {:?}, private_key: {:?}",
        pk_hex, sk_hex
    );
    Ok((sk_hex, pk_hex))
}

/// Generates a new BLS secret key from randomness
pub fn new_bls_key() -> Result<SecretKey> {
    // rng
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    // key gen
    let sk = SecretKey::key_gen(&ikm, &[]);

    match sk.as_ref().err() {
        Some(BLST_ERROR::BLST_SUCCESS) | None => Ok(sk.unwrap()),
        Some(_) => bail!("Failed to generate BLS sk"),
    }
}

/// Generates and saves BLS secret key, using derived pk_hex as file identifier (omitting '0x' prefix)
pub fn bls_key_gen(save_key: bool) -> Result<PublicKey> {
    let sk = new_bls_key()?;
    let pk = sk.sk_to_pk();
    let pk_bytes: [u8; 48] = sk.sk_to_pk().compress();

    // compress pk to 48B
    let pk_hex: String = hex::encode(pk_bytes);
    let sk_hex: String = hex::encode(sk.to_bytes());

    // save secret key using pk_hex as file identifier (omitting '0x' prefix)
    if save_key {
        let name = new_keystore(
            &Path::new("./etc/keys/bls_keys/generated"),
            "pufifish", // todo
            &pk_hex,
            &sk.serialize()
        )?;
        println!("Saved keystore: {name}");
    }

    Ok(pk)
}

pub fn bls_pk_from_hex(pk_hex: String) -> Result<PublicKey> {
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    let pk_bytes = hex::decode(&pk_hex)?;
    match PublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => Ok(pk),
        Err(e) => bail!(
            "failed to recover BLS pk from pk_hex: {}, error: {:?}",
            pk_hex,
            e
        ),
    }
}

pub fn bls_sk_from_hex(sk_hex: String) -> Result<SecretKey> {
    let sk_hex: String = sk_hex.strip_prefix("0x").unwrap_or(&sk_hex).into();
    let sk_bytes = hex::decode(sk_hex)?;
    match SecretKey::from_bytes(&sk_bytes) {
        Ok(sk) => Ok(sk),
        Err(e) => bail!("failed to recover BLS sk from sk_hex, error: {:?}", e),
    }
}

pub fn bls_sig_from_hex(sig_hex: String) -> Result<Signature> {
    let sig_hex: String = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex).into();
    let sig_bytes = hex::decode(sig_hex)?;
    match Signature::from_bytes(&sig_bytes) {
        Ok(sig) => Ok(sig),
        Err(e) => bail!("failed to recover BLS sig from sig_hex, error: {:?}", e),
    }
}

/// Returns Ok() if `sig` is a valid BLS signature
pub fn verify_bls_sig(sig: Signature, pk: PublicKey, msg: &[u8]) -> Result<()> {
    match sig.verify(
        true,         // sig_groupcheck
        msg,          // msg
        CIPHER_SUITE, // dst
        &[],          // aug
        &pk,          // pk
        true,
    ) {
        // pk_validate
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => bail!("BLS Signature verifcation failed"),
    }
}

/// Performs BLS signature on `msg` using the BLS secret key looked up from memory
/// with pk_hex as the file identifier.
pub fn bls_sign(pk_hex: &String, msg: &[u8]) -> Result<Signature> {
    // the sk is either imported or generated or does not exist:
    let sk = match read_bls_key(&format!("imported/{}", pk_hex)) {
        Ok(sk) => sk,
        Err(_) => match read_bls_key(&format!("generated/{}", pk_hex)) {
            Ok(sk) => sk,
            Err(e) => bail!("Secret key for pk: {} not found", pk_hex),
        },
    };

    let exp_pk = bls_pk_from_hex(pk_hex.to_owned())
        .with_context(|| format!("failed to read pk: {} in bls_sign()", pk_hex))?;

    // valid keypair
    if sk.sk_to_pk() != exp_pk {
        bail!("Mismatch with input and derived pk");
    }
    println!("DEBUG: sk recovered {:?}", sk);

    // sign the message
    let sig = sk.sign(msg, CIPHER_SUITE, &[]);

    // verify the signatures correctness
    verify_bls_sig(sig, exp_pk, msg)?;

    // Return the BLS signature
    Ok(sig)
}

/// Writes the hex-encoded secret key to a file named from `fname`
pub fn write_key(fname: &String, sk_hex: &String) -> Result<()> {
    let file_path: PathBuf = ["./etc/keys/", fname.as_str()].iter().collect();
    if let Some(p) = file_path.parent() {
        fs::create_dir_all(p).with_context(|| "Failed to create keys dir")?
    };
    fs::write(&file_path, sk_hex).with_context(|| "failed to write sk")
}

/// Reads hex-encoded secret key from a file named from `pk_hex` and converts it to a BLS SecretKey
pub fn read_bls_key(pk_hex: &String) -> Result<SecretKey> {
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    let file_path: PathBuf = ["./etc/keys/bls_keys/", pk_hex.as_str()].iter().collect();
    let sk_rec_bytes = decrypt_key(file_path, "pufifish")?; // todo
    let sk_res = SecretKey::from_bytes(&sk_rec_bytes);

    match sk_res.as_ref().err() {
        Some(BLST_ERROR::BLST_SUCCESS) | None => Ok(sk_res.unwrap()),
        _ => bail!("Could not read_bls_key from pk_hex {}", pk_hex),
    }
}

/// Reads hex-encoded secret key from a file named from `pk_hex` and converts it to an Eth SecretKey
pub fn read_eth_key(fname: &String) -> Result<EthSecretKey> {
    let fname: String = fname.strip_prefix("0x").unwrap_or(&fname).into();
    if fname.len() != 66 {
        bail!("ETH key hex string should be derived from compressed (33 byte) pk")
    }
    let file_path: PathBuf = ["./etc/keys/eth_keys", fname.as_str()].iter().collect();
    let sk_rec_bytes = fs::read(&file_path).with_context(|| "Unable to read eth secret key")?;
    let sk_rec_dec = hex::decode(sk_rec_bytes).with_context(|| "Unable to decode sk hex")?;
    EthSecretKey::parse_slice(&sk_rec_dec).with_context(|| "couldn't parse sk bytes to eth sk type")
}

pub fn list_keys(path: &str) -> Result<Vec<String>> {
    let paths = fs::read_dir(path).with_context(|| "No keys saved in dir")?;

    let mut keys: Vec<String> = Vec::new();
    for path in paths {
        // Get the paths to each file in this dir
        let p = match path.as_ref().err() {
            Some(e) => bail!("failed to find path: {}", e),
            _ => path.unwrap(),
        };

        // remove path prefix, to grab just the file name
        let fname = p.file_name();

        match fname.to_os_string().into_string() {
            Ok(s) => keys.push(s),
            Err(e) => bail!("Error, bad file name in list_keys(): {:?}", e),
        }
    }
    Ok(keys)
}

/// Returns the file names of each of the saved bls secret keys, where each fname
/// is assumed to be the compressed public key in hex without the `0x` prefix.
pub fn list_imported_bls_keys() -> Result<Vec<String>> {
    list_keys("./etc/keys/bls_keys/imported")
}

/// Returns the file names of each of the saved bls secret keys, where each fname
/// is assumed to be the compressed public key in hex without the `0x` prefix.
pub fn list_generated_bls_keys() -> Result<Vec<String>> {
    list_keys("./etc/keys/bls_keys/generated")
}

/// Returns the file names of each of the saved eth secret keys, where each fname
/// is assumed to be the eth wallet address derived from the eth public key in hex without the `0x` prefix.
pub fn list_eth_keys() -> Result<Vec<String>> {
    list_keys("./etc/keys/eth_keys")
}

/// Generates a BLS secret key then encrypts via ECDH using pk_hex
pub fn bls_key_provision(eth_pk_hex: &String) -> Result<(String, String)> {
    let sk = new_bls_key()?;
    let pk = sk.sk_to_pk();
    let bls_pk_hex = hex::encode(pk.compress());
    let receiver_pub = hex::decode(eth_pk_hex).with_context(|| {
        format!(
            "couldnt decode eth_pk_hex in bls_key_provision: {}",
            eth_pk_hex
        )
    })?;

    let ct_sk_bytes = encrypt(&receiver_pub, &sk.serialize())
        .with_context(|| format!("Couldn't encrypt bls sk with pk {}", eth_pk_hex))?;

    let ct_sk_hex = hex::encode(ct_sk_bytes);

    println!("provisioned bls key: {}", bls_pk_hex);
    // Save the public bls key (NOT the sk)
    write_key(&format!("provisioned/{}", bls_pk_hex), &bls_pk_hex)?;

    Ok((ct_sk_hex, bls_pk_hex))
}

/// Generates `n` BLS secret keys and derives one `n/n` aggregate public key from it
pub fn dist_bls_key_gen(n: usize) -> Result<(AggregatePublicKey, Vec<SecretKey>)> {
    // generate n sks
    let mut sks: Vec<SecretKey> = Vec::new();
    for i in 0..n {
        match new_bls_key() {
            Ok(sk) => sks.push(sk),
            Err(e) => bail!(
                "Failed to generate BLS sk {} in dist_bls_key_gen(), blst error: {}",
                i,
                e
            ),
        }
    }

    // derive n pks
    let pks: Vec<PublicKey> = sks
        .iter()
        .map(|sk| {
            let pk = sk.sk_to_pk();
            println!("pk: {:?}", hex::encode(pk.to_bytes()));
            pk
        })
        .collect();
    let pks_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();

    // aggregate the n BLS public keys into 1 aggregate pk
    let agg_pk_res = AggregatePublicKey::aggregate(&pks_refs, true);
    match agg_pk_res.err() {
        Some(BLST_ERROR::BLST_SUCCESS) | None => {
            let agg_pk = agg_pk_res.unwrap();
            println!(
                "agg_pk: {:?}",
                hex::encode(agg_pk.to_public_key().to_bytes())
            );
            Ok((agg_pk, sks))
        }
        _ => bail!("Failed to aggregate BLS pub keys"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecies::PublicKey as EthPublicKey;
    use ecies::SecretKey as EthSecretKey;

    #[test]
    fn bls_key_gen_produces_valid_keys_and_sig() -> Result<()> {
        let pk: PublicKey = bls_key_gen(true)?;
        let pk_hex = hex::encode(pk.compress());
        let msg = b"yadayada";
        let sig = bls_sign(&pk_hex, msg)?;
        verify_bls_sig(sig, pk, msg)?;
        Ok(())
    }

    #[test]
    fn eth_key_gen_encryption_works() -> Result<()> {
        let (sk, pk) = new_eth_key()?;
        let msg = b"yadayada";

        // encrypt msg
        let ct = match encrypt(&pk.serialize(), msg) {
            Ok(ct) => ct,
            Err(_) => panic!("Couldn't encrypt msg"),
        };

        // decrpyt msg
        let data = match decrypt(&sk.serialize(), &ct) {
            Ok(pt) => pt,
            Err(_) => panic!("Couldn't decrypt msg"),
        };

        assert_eq!(msg.to_vec(), data);

        Ok(())
    }

    #[test]
    fn eth_key_gen_key_management() -> Result<()> {
        // gen key and save it to file
        let pk = eth_key_gen()?;
        // rederive eth wallet address filename
        let fname = eth_pk_to_hex(&pk);
        // read sk from file
        let sk = read_eth_key(&fname)?;

        let msg = b"yadayada";

        // encrypt msg
        let ct = match encrypt(&pk.serialize(), msg) {
            Ok(ct) => ct,
            Err(_) => panic!("Couldn't encrypt msg"),
        };

        // decrpyt msg
        let data = match decrypt(&sk.serialize(), &ct) {
            Ok(pt) => pt,
            Err(_) => panic!("Couldn't decrypt msg"),
        };

        assert_eq!(msg.to_vec(), data);

        Ok(())
    }

    #[test]
    fn test_bls_key_provision() -> Result<()> {
        // new eth key pair (assumed the requester knows sk)
        let (sk, pk) = new_eth_key()?;

        let pk_hex = hex::encode(pk.serialize());

        // provision a bls key that is encrypted using ecies and bls_pk
        let (ct_bls_sk_hex, bls_pk) = bls_key_provision(&pk_hex)?;

        // hex decode
        let ct_bls_sk = hex::decode(ct_bls_sk_hex)?;

        // requester can decrypt ct_bls_sk
        let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk)?;

        // the BLS sk can be recovered from bytes
        let bls_sk = SecretKey::from_bytes(&bls_sk_bytes).unwrap();

        // assert this recovered bls sk derives the expected bls pk
        assert_eq!(hex::encode(bls_sk.sk_to_pk().compress()), bls_pk);

        Ok(())
    }

    #[test]
    fn test_distribute_encrypted_bls_keys() -> Result<()> {
        // number of nodes
        const n: usize = 10;

        // generate n eth keys (saving them to fs)
        let eth_pks: Vec<EthPublicKey> =
            (0..n).into_iter().map(|_| eth_key_gen().unwrap()).collect();

        // hex encode pks
        let pk_hexs: Vec<String> = eth_pks.iter().map(|pk| eth_pk_to_hex(pk)).collect();

        // lookup n eth secret keys
        let eth_sks: Vec<EthSecretKey> = pk_hexs
            .iter()
            .map(|addr| read_eth_key(addr).unwrap())
            .collect();

        // generate n BLS keys
        let (agg_pk, bls_sks) = dist_bls_key_gen(n)?;

        // encrypt each bls sk
        let ct_bls_sks: Vec<Vec<u8>> = eth_pks
            .iter()
            .zip(bls_sks.iter())
            .map(|(eth_pk, bls_sk)| {
                encrypt(&eth_pk.serialize(), &bls_sk.serialize()).expect("Could not encrpyt bls sk")
            })
            .collect();

        // decrypt each encrypted bls sk
        let pt_bls_sks: Vec<SecretKey> = eth_sks
            .iter()
            .zip(ct_bls_sks.iter())
            .map(|(eth_sk, ct_bls_sk)| {
                let sk_bytes =
                    decrypt(&eth_sk.serialize(), &ct_bls_sk).expect("Could not encrpyt bls sk");
                SecretKey::from_bytes(&sk_bytes).expect("couldnt convert to BLS key")
            })
            .collect();

        // verify we decrypted the correct BLS secret key
        pt_bls_sks
            .iter()
            .zip(bls_sks.iter())
            .for_each(|(sk_got, sk_exp)| assert_eq!(sk_got.serialize(), sk_exp.serialize()));
        Ok(())
    }
}
