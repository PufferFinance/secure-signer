use crate::strip_0x_prefix;

use super::eth_keys;
use anyhow::{Context, Result};
use ecies::SecretKey as EthSecretKey;
use eth_keystore::decrypt_keystore;

pub fn import_keystore(
    keystore: &String,
    ct_password_hex: &String,
    envelope_sk: &EthSecretKey,
) -> Result<Vec<u8>> {
    // Decrypt the password
    let ct_password_hex: String = strip_0x_prefix!(ct_password_hex);
    let ct_password_bytes = hex::decode(ct_password_hex)?;
    let password_bytes = eth_keys::envelope_decrypt(envelope_sk, &ct_password_bytes)?;
    let password = String::from_utf8(password_bytes).with_context(|| "non-utf8 password")?;
    decrypt_keystore(keystore, password).with_context(|| "Failed to decrypt keystore")
}

#[cfg(test)]
pub mod keystore_tests {
    use crate::crypto::eth_keys;

    use super::import_keystore;
    use hex::FromHex;

    #[test]
    /// Test vec from: https://eips.ethereum.org/EIPS/eip-2335
    fn test_import_keystore() {
        let keystore = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }"#.to_string();

        let (eth_sk, eth_pk) = eth_keys::new_eth_key().unwrap();
        let encoded_pw = hex::decode("7465737470617373776f7264f09f9491").unwrap();
        let ct_pw = eth_keys::envelope_encrypt(&eth_pk, &encoded_pw).unwrap();

        let bls_sk_bytes = import_keystore(&keystore, &hex::encode(ct_pw), &eth_sk).unwrap();

        assert_eq!(
            bls_sk_bytes,
            Vec::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_keystore() {
        std::fs::create_dir_all("./test_keys").unwrap();
        let secret =
            Vec::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let dir = std::path::Path::new("./test_keys");
        let mut rng = rand::thread_rng();
        let name = eth_keystore::encrypt_key(&dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(eth_keystore::decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(eth_keystore::decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
        std::fs::remove_dir_all("./test_keys").ok();
    }
}
