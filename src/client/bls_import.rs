use std::{fs::{read_to_string, File}, path::{Path, PathBuf}, io::Write};

use super::routes::{bls_key_import, eth_keygen};
use puffersecuresigner::{
    api::{KeyGenResponse, KeyImportRequest, KeyImportResponse},
    constants::ETH_COMPRESSED_PK_BYTES,
    crypto::eth_keys,
};

use anyhow::{bail, Context, Result};
use ecies::PublicKey as EthPublicKey;
use log::info;

fn validate_eth_ra(resp: KeyGenResponse) -> Result<EthPublicKey> {
    // Verify the report is valid
    resp.evidence.verify_intel_signing_certificate()?;

    // Verify the payload
    let pk = eth_keys::eth_pk_from_hex(&resp.pk_hex)?;

    // Read the 64B payload from RA report
    let got_payload: [u8; 64] = resp.evidence.get_report_data()?;

    // Verify the first ETH_COMPRESSED_PK_BYTES contains the expected ETH comporessed public key
    if &got_payload[0..ETH_COMPRESSED_PK_BYTES] != pk.serialize_compressed() {
        bail!("Remote attestation payload does not match the expected")
    }
    Ok(pk)
}

fn encrypt_password(password: &String, encrypting_pk: &EthPublicKey) -> Result<String> {
    // Envelope encrypt the keystore password
    let ct_pw = eth_keys::envelope_encrypt(encrypting_pk, password.as_bytes())?;
    let ct_password_hex = hex::encode(&ct_pw);
    Ok(ct_password_hex)
}

pub async fn import_from_files(
    port: u16,
    keystore_file: PathBuf,
    password_file: PathBuf,
    slash_protection_file: Option<PathBuf>,
    mrenclave: &str,
) -> Result<KeyImportResponse> {
    // Read keystore file
    let keystore = read_to_string(keystore_file.clone())
        .with_context(|| format!("Failed to read keystore file: {:?}", keystore_file))?;

    // Read slash_protection file
    let slashing_protection = match slash_protection_file {
        Some(path) => {
            let content = read_to_string(path.clone())
                .with_context(|| format!("Failed to read slash protection file: {:?}", path))?;
            Some(content)
        }
        None => None,
    };

    // Read password file
    let password = read_to_string(password_file.clone())
        .with_context(|| format!("Failed to read password file: {:?}", password_file))?;

    // Request a new ETH key + remote attestation
    let resp: KeyGenResponse = eth_keygen(port).await?;

    // Verify remote attestation evidence
    // let enclave_eth_pk = validate_eth_ra(resp)?; // todo only should run if we know we are talking to sgx
    let enclave_eth_pk = eth_keys::eth_pk_from_hex(&resp.pk_hex)?;
    let encrypting_pk_hex = eth_keys::eth_pk_to_hex(&enclave_eth_pk);
    info!("Using enclave generated eth pk to encrypt password: {encrypting_pk_hex}");
    // todo compare to mrenclave

    // Encrypt the password
    let ct_password_hex = encrypt_password(&password, &enclave_eth_pk)?;

    // Build the key import request
    let req = KeyImportRequest {
        keystore,
        ct_password_hex,
        slashing_protection,
        encrypting_pk_hex,
    };
    let json_req = serde_json::to_string(&req)?;
    bls_key_import(port, &json_req).await
}

#[tokio::test]
async fn dummy_import() {
    let temp_dir = std::env::temp_dir();

    let keystore = r#"
    {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }"#.to_string();

    // Write file to /tmp/keystore
    let keystore_path = temp_dir.join("test_keystore.json");
    let mut keystore_file = File::create(&keystore_path).unwrap();
    write!(keystore_file, "{}", keystore).unwrap();


    // Write file to /tmp/password
    let encoded_pw = vec![
        116, 101, 115, 116, 112, 97, 115, 115, 119, 111, 114, 100, 240, 159, 148, 145,
    ];
    let password = String::from_utf8(encoded_pw).unwrap();
    let password_path = temp_dir.join("test_password.txt");
    let mut password_file = File::create(&password_path).unwrap();
    write!(password_file, "{}", password).unwrap();

    // Write file to /tmp/slashing_protection
    let slashing_protection = r#"
    {
        "metadata": {
          "interchange_format_version": "5",
          "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
        },
        "data": [
          {
            "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "signed_blocks": [
              {
                "slot": "81952",
                "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
              },
              {
                "slot": "81951"
              }
            ],
            "signed_attestations": [
              {
                "source_epoch": "2290",
                "target_epoch": "3007",
                "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
              },
              {
                "source_epoch": "2290",
                "target_epoch": "3008"
              }
            ]
          }
        ]
    }"#.to_string();
    let slashing_protection_path = temp_dir.join("test_slashing_protection.json");
    let mut slashing_protection_file = File::create(&slashing_protection_path).unwrap();
    write!(slashing_protection_file, "{}", slashing_protection).unwrap();

    let port = 9001;
    let mrenclave = "9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94";
    let result = import_from_files(
        port,
        keystore_path.clone(),
        password_path.clone(),
        Some(slashing_protection_path.clone()),
        mrenclave
    )
    .await;

    assert!(result.is_ok(), "Import from files failed: {:?}", result);

    // Clean up temporary files
    std::fs::remove_file(keystore_path).unwrap();
    std::fs::remove_file(password_path).unwrap();
    std::fs::remove_file(slashing_protection_path).unwrap();
}
