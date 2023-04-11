use crate::constants::{ETH_COMPRESSED_PK_BYTES, ETH_SIGNATURE_BYTES};
use crate::io::key_management::{read_eth_key, write_eth_key};
use crate::strip_0x_prefix;

use ecies::{PublicKey as EthPublicKey, SecretKey as EthSecretKey, utils::generate_keypair};
use libsecp256k1::{Message, Signature};
use sha3::{Digest, Keccak256};
use anyhow::{bail, Context, Result};

/// Wrapper around ecies utility function to generate SECP256K1 keypair
pub fn new_eth_key() -> Result<(EthSecretKey, EthPublicKey)> {
    Ok(generate_keypair())
}

/// Generates fresh ETH keypair, then saves the key using the
/// ETH address derived from the public key as the filename.
pub fn eth_key_gen() -> Result<EthPublicKey> {
    let (sk, pk) = new_eth_key()?;
    save_eth_key(sk, pk).with_context(|| "Failed to save generated ETH key")
}

/// Hex-encode ETH secret key
pub fn eth_sk_to_hex(sk: &EthSecretKey) -> String {
    strip_0x_prefix!(hex::encode(sk.serialize()))
}

/// Converts SECP256K1 key to compressed 33 bytes then hex-encodes
pub fn eth_pk_to_hex(pk: &EthPublicKey) -> String {
    strip_0x_prefix!(hex::encode(pk.serialize_compressed()))
}

/// Derives an ETH public key from a hex-string, expects the hex string to be in compressed 33B form
pub fn eth_pk_from_hex(pk_hex: &String) -> Result<EthPublicKey> {
    let pk_hex: String = strip_0x_prefix!(pk_hex);
    let pk_bytes = hex::decode(&pk_hex)?;

    if pk_bytes.len() != ETH_COMPRESSED_PK_BYTES {
        bail!("ETH pk should be in compressed 33B form")
    }

    let mut pk_compressed_bytes = [0_u8; ETH_COMPRESSED_PK_BYTES];
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

/// Derives an ETH public key from a hex-string, expects the hex string to be in compressed 33B form
pub fn eth_sk_from_bytes(sk: Vec<u8>) -> Result<EthSecretKey> {
    EthSecretKey::parse_slice(&sk).with_context(|| "couldn't parse sk bytes to eth sk type")
}

/// Write the ETH SECP256K1 secret key to a secure file using the hex encoded pk as filename
fn save_eth_key(sk: EthSecretKey, pk: EthPublicKey) -> Result<EthPublicKey> {
    let pk_hex = eth_pk_to_hex(&pk);
    dbg!("new enclave eth pk: 0x{}", &pk_hex);

    let sk_hex = eth_sk_to_hex(&sk);

    write_eth_key(&pk_hex, &sk_hex).with_context(|| "eth sk failed to save")?;

    Ok(pk)
}

/// Read the ETH SECP256K1 secret key from a secure file using the hex encoded pk as filename
pub fn fetch_eth_key(pk_hex: &String) -> Result<EthSecretKey> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let sk_bytes = read_eth_key(pk_hex)?;
    eth_sk_from_bytes(sk_bytes)
}

/// Computes digest = keccak256(message), then signs digest using SECP256K1 secret key.
/// Upon success returns the signature and digest.
pub fn sign_message(message: &[u8], secret_key: &EthSecretKey) -> Result<(Signature, Message)> {
    // Hash the message with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(message);
    let digest_bytes = hasher.finalize();

    // Create a Message object from the hash
    let digest = Message::parse_slice(&digest_bytes)
        .with_context(|| "Failed to parse the message hash into a libsecp256k1 Message")?;

    // Sign the message using the secret key
    let (signature, _) = libsecp256k1::sign(&digest, &secret_key);
    Ok((signature, digest))
}

/// Verify the signature over keccak256(message) using SECP256K1 secret key
pub fn verify_message(message: &[u8], signature: &[u8; ETH_SIGNATURE_BYTES], public_key: &EthPublicKey) -> Result<bool> {
    // Hash the message with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(message);
    let digest_bytes = hasher.finalize();

    // Create a Message object from the hash
    let digest = Message::parse_slice(&digest_bytes)
        .with_context(|| "Failed to parse the message hash into a libsecp256k1 Message")?;

    let signature =
        Signature::parse_standard(signature).with_context(|| "Invalid signature encoding")?;
    Ok(libsecp256k1::verify(&digest, &signature, &public_key))
}

/// Use ECIES to encrypt the message using the provided public key. The encrypted message
/// can only be decrypted by the owner of the corresponding private key.
pub fn envelope_encrypt(public_key: &EthPublicKey, message: &[u8]) -> Result<Vec<u8>> {
    // Encrypt the message using the public key
    let encrypted_message = ecies::encrypt(&public_key.serialize(), message)
        .with_context(|| "Failed to encrypt the message using the provided public key")?;

    Ok(encrypted_message)
}

/// Use ECIES to decrypt the encrypted message using the provided secret key. This function
/// will fail if the encrypted message was not encrypted using the corresponding public key.
pub fn envelope_decrypt(secret_key: &EthSecretKey, encrypted_message: &[u8]) -> Result<Vec<u8>> {
    // Decrypt the encrypted message using the secret key
    let decrypted_message = ecies::decrypt(&secret_key.serialize(), encrypted_message)
        .with_context(|| "Failed to decrypt the message using the provided secret key")?;

    Ok(decrypted_message)
}

/// Wrapper over `envelope_decrypt` that fetches the secret key corresponding to the
/// provided `eth_pk_hex` from the saved secret key file and uses it to decrypt the
/// encrypted message.
pub fn envelope_decrypt_from_saved_sk(eth_pk_hex: String, encrypted_message: &[u8]) -> Result<Vec<u8>> {
    // Fetch the secret key from file
    let secret_key = fetch_eth_key(&eth_pk_hex)?;

    // Decrypt the encrypted message using the fetched secret key by calling the generic envelope_decrypt function
    let decrypted_message = envelope_decrypt(&secret_key, &encrypted_message)?;

    Ok(decrypted_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecies::PublicKey as EthPublicKey;
    use ecies::SecretKey as EthSecretKey;

    #[test]
    fn test_sign_message() {
        // Generate a new SECP256K1 keypair (ETH keypair)
        let (secret_key, public_key) = new_eth_key().unwrap();

        // Create a message to sign
        let message = b"Test message for signing.";

        // Sign the message
        let (signature, digest_to_sign) = sign_message(&message[..], &secret_key).unwrap();

        // Verify the signature using the public key
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let digest_bytes = hasher.finalize();
        let digest = Message::parse_slice(&digest_bytes).unwrap();
        assert_eq!(digest, digest_to_sign);

        let is_valid = libsecp256k1::verify(&digest_to_sign, &signature, &public_key);

        // The signature should be valid
        assert!(is_valid);
    }

    #[test]
    fn test_verify_message() {
        // Generate a new SECP256K1 keypair (ETH keypair)
        let (secret_key, public_key) = new_eth_key().unwrap();

        // Create a message to sign
        let message: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz123456";
        dbg!(hex::encode(&message));

        // Sign the message
        let (signature, digest_to_sign) = sign_message(&message[..], &secret_key).unwrap();
        dbg!(hex::encode(&signature.serialize()));
        assert!(libsecp256k1::verify(
            &digest_to_sign,
            &signature,
            &public_key
        ));

        // Verify the signature using the verify_message function
        let is_valid = verify_message(message, &signature.serialize(), &public_key).unwrap();

        // The signature should be valid
        assert!(is_valid);
    }

    #[test]
    fn test_eth_sk_pk_to_hex() {
        let (secret_key, public_key) = new_eth_key().unwrap();

        let secret_key_hex = eth_sk_to_hex(&secret_key);
        let public_key_hex = eth_pk_to_hex(&public_key);

        assert_eq!(secret_key_hex, hex::encode(secret_key.serialize()));
        assert_eq!(
            public_key_hex,
            hex::encode(public_key.serialize_compressed())
        );
        assert_ne!(public_key_hex, hex::encode(public_key.serialize()));

        assert_eq!(secret_key_hex.len(), 64);
        assert_eq!(public_key_hex.len(), 66); // 33 bytes compressed * 2 (hex encoding) = 66 characters
    }

    #[test]
    fn test_eth_pk_from_hex() {
        let (secret_key, public_key) = new_eth_key().unwrap();

        let public_key_hex = eth_pk_to_hex(&public_key);
        let recovered_public_key = eth_pk_from_hex(&public_key_hex.clone()).unwrap();

        assert_eq!(public_key, recovered_public_key);
    }

    #[test]
    fn test_eth_sk_from_bytes() {
        let (secret_key, _public_key) = new_eth_key().unwrap();

        let secret_key_bytes = secret_key.serialize().to_vec();
        let recovered_secret_key = eth_sk_from_bytes(secret_key_bytes).unwrap();

        assert_eq!(secret_key, recovered_secret_key);
    }

    #[test]
    fn test_save_fetch_eth_key() {
        let (secret_key, public_key) = new_eth_key().unwrap();
        let public_key_hex = eth_pk_to_hex(&public_key);

        // Save the secret key
        let saved_public_key = save_eth_key(secret_key.clone(), public_key.clone()).unwrap();
        assert_eq!(public_key, saved_public_key);

        // Fetch the secret key
        let fetched_secret_key = fetch_eth_key(&public_key_hex).unwrap();
        assert_eq!(secret_key, fetched_secret_key);
    }

    #[test]
    fn test_envelope_encrypt_and_decrypt() {
        // Generate a new SECP256K1 keypair (ETH keypair)
        let (secret_key, public_key) = new_eth_key().unwrap();

        // Create a message to encrypt
        let message = b"Test message for encryption.";

        // Encrypt the message
        let encrypted_message = envelope_encrypt(&public_key, &message[..]).unwrap();

        // Decrypt the encrypted message
        let decrypted_message = envelope_decrypt(&secret_key, &encrypted_message).unwrap();

        // The decrypted message should be the same as the original message
        assert_eq!(message.to_vec(), decrypted_message);
    }

    #[test]
    fn test_envelope_decrypt_from_saved_sk() {
        // Generate a new SECP256K1 keypair (ETH keypair) and save the secret key to a file
        let (secret_key, public_key) = new_eth_key().unwrap();
        let eth_pk_hex = eth_pk_to_hex(&public_key);
        save_eth_key(secret_key, public_key).unwrap();

        // Create a message to encrypt
        let message = b"Test message for encryption.";

        // Encrypt the message
        let encrypted_message = envelope_encrypt(&public_key, &message[..]).unwrap();

        // Decrypt the encrypted message using the saved secret key
        let decrypted_message = envelope_decrypt_from_saved_sk(eth_pk_hex, &encrypted_message).unwrap();

        // The decrypted message should be the same as the original message
        assert_eq!(message.to_vec(), decrypted_message);
    }
}
