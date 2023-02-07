use anyhow::{bail, Context, Result};

use blst::min_pk::{AggregatePublicKey, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use ecies::PublicKey as EthPublicKey;
use ecies::SecretKey as EthSecretKey;
use ecies::{decrypt, encrypt, utils::generate_keypair};
use eth_keystore::{decrypt_key, encrypt_key};
use log::{debug, error, info};
use rand::RngCore;

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

/// write the Eth SECP256K1 secret key to a secure file using the hex encoded pk as filename
fn save_eth_key(sk: EthSecretKey, pk: EthPublicKey) -> Result<EthPublicKey> {
    let pk_hex = eth_pk_to_hex(&pk);
    println!("new enclave pk: 0x{}", pk_hex);

    let sk_hex = eth_sk_to_hex(&sk);

    write_key(&format!("eth_keys/{}", pk_hex), &sk_hex).with_context(|| "eth sk failed to save")?;

    Ok(pk)
}

pub fn envelope_decrypt_password(ct_pw: String, pubkey: String) -> Result<String> {
    // fetch safeguarded ETH private key
    let sk = read_eth_key(&pubkey)?;
    let ct_password_hex: String = ct_pw.strip_prefix("0x").unwrap_or(&ct_pw).into();
    let ct_password_bytes = hex::decode(&ct_password_hex)?;
    // get plaintext password
    let password_bytes = decrypt(&sk.serialize(), &ct_password_bytes)?;
    let password = String::from_utf8(password_bytes).with_context(|| "non-utf8 password")?;
    Ok(password)
}

pub fn new_keystore(p: &Path, password: &str, name: &str, sk_bytes: &[u8]) -> Result<String> {
    fs::create_dir_all(p).with_context(|| "Failed to create dir for keystore")?;
    let mut rng = rand::thread_rng();
    // Generates a new Scrypt keystore
    let name = encrypt_key(p, &mut rng, sk_bytes, password, Some(name))?;
    Ok(name)
}

pub fn load_keystore(
    keystore_path: &String,
    keystore_password: &String,
) -> Result<(String, String)> {
    let sk_bytes = decrypt_key(Path::new(keystore_path), keystore_password)?;
    let pk = bls_sk_from_hex(hex::encode(&sk_bytes))?.sk_to_pk();

    let sk_hex = "0x".to_string() + &hex::encode(&sk_bytes);
    let pk_hex = "0x".to_string() + &hex::encode(pk.compress());
    Ok((sk_hex, pk_hex))
}

pub fn decrypt_keystore(keystore_str: &String, keystore_password: &String) -> Result<Vec<u8>> {
    // temporarily save keystore
    let temp_path = "./etc/keys/temp";
    fs::write(temp_path, keystore_str)?;

    // decrypt keystore
    let sk_bytes = match decrypt_key(Path::new(temp_path), keystore_password) {
        Ok(bs) => bs,
        Err(e) => {
            fs::remove_file(temp_path)?;
            bail!("Couldn't decrypt keystore")
        }
    };

    // delete temp keystore
    fs::remove_file(temp_path)?;

    Ok(sk_bytes)
}

pub fn load_then_save_keystore(
    keystore_str: &String,
    keystore_password: &String,
) -> Result<String> {
    // temporarily save keystore
    let temp_path = "./etc/keys/temp";
    fs::write(temp_path, keystore_str)?;
    // decrypt keystore
    let sk_bytes = match decrypt_key(Path::new(temp_path), keystore_password) {
        Ok(bs) => bs,
        Err(e) => {
            fs::remove_file(temp_path)?;
            bail!("Couldn't decrypt keystore")
        }
    };
    let pk = match bls_sk_from_hex(hex::encode(&sk_bytes)) {
        Ok(pk) => pk.sk_to_pk(),
        Err(e) => {
            fs::remove_file(temp_path)?;
            bail!("Couldn't convert bls sk")
        }
    };
    let pk_hex = hex::encode(pk.compress());

    // delete temp keystore
    fs::remove_file(temp_path)?;

    // generate a new keystore
    let keystore_path = "./etc/keys/bls_keys/imported/";
    new_keystore(Path::new(keystore_path), "", &pk_hex, &sk_bytes)?;
    let prefixed_pk_hex: String = "0x".to_owned() + &pk_hex;
    Ok(prefixed_pk_hex)
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
            "",
            &pk_hex,
            &sk.serialize(),
        )?;
        println!("Saved keystore: {name}");
    }

    Ok(pk)
}

/// Converts SECP256K1 key to compressed 33 bytes
pub fn bls_pk_to_hex(pk: &PublicKey) -> String {
    hex::encode(pk.compress())
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
        error!("Derived pubkey does not match expected");
        bail!("Mismatch with input and derived pk");
    }

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
    let sk_rec_bytes = decrypt_key(file_path, "")?;
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
}
