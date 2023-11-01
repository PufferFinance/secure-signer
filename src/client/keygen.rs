use anyhow::Result;
use ecies::PublicKey as EthPublicKey;

pub fn generate_bls_keystore_handler(
    keygen_payload: crate::enclave::types::AttestFreshBlsKeyPayload,
    keystore_password: &String,
) -> Result<crate::enclave::types::BlsKeygenPayload> {
    log::info!("generate_bls_keystore()");
    generate_bls_keystore(
        keygen_payload.withdrawal_credentials,
        keygen_payload.guardian_pubkeys,
        keygen_payload.threshold,
        keystore_password,
    )
}

fn generate_bls_keystore(
    withdrawal_credentials: [u8; 32],
    guardian_public_keys: Vec<EthPublicKey>,
    threshold: usize,
    password: &String,
) -> Result<crate::enclave::types::BlsKeygenPayload> {
    // Generate a SecretKeySet where t + 1 signature shares can be combined into a full signature. attest_fresh_bls_key() function assumes `threshold = t + 1`, so we must pass new_bls_key(t=threshold - 1)
    let secret_key_set = crate::crypto::bls_keys::new_bls_key(threshold - 1);

    // Shard the key into `n` keyshares
    let n = guardian_public_keys.len();
    let key_shares = crate::crypto::bls_keys::distribute_key_shares(&secret_key_set, n);

    // Encrypt the shares to using guardian pubkeys
    let mut recipient_keys: Vec<crate::enclave::validator::EncryptedRecipientKeys> = Vec::new();
    for (g_pk, (sk_share, pk_share)) in guardian_public_keys.into_iter().zip(key_shares.into_iter())
    {
        let k = crate::enclave::validator::RecipientKeys {
            guardian_public_key: g_pk,
            secret_key_share: sk_share,
            public_key_share: pk_share,
        }
        .encrypt_to_recipient()?;
        recipient_keys.push(k);
    }

    // Get validator aggregate public key
    let validator_pubkey = secret_key_set.public_keys().public_key();

    // Save validator private key to encrypted keystore
    crate::crypto::bls_keys::save_bls_keystore(&secret_key_set, &password)?;

    // Sign DepositMessage to deposit 32 ETH to beacon deposit contract
    let (signature, deposit_data_root) = crate::eth2::eth_signing::sign_full_deposit(
        &secret_key_set,
        withdrawal_credentials.clone(),
        crate::eth2::eth_types::GENESIS_FORK_VERSION,
    )?;

    // Return the payload
    Ok(crate::enclave::types::BlsKeygenPayload {
        bls_pub_key_set: hex::encode(secret_key_set.public_keys().to_bytes()),
        bls_pub_key: validator_pubkey.to_hex(),
        signature: hex::encode(&signature[..]),
        deposit_data_root: hex::encode(deposit_data_root),
        bls_enc_priv_key_shares: recipient_keys
            .iter()
            .map(|encrypted_key| encrypted_key.encrypted_secret_key_share_hex.clone())
            .collect(),
        intel_report: "".to_string(),
        intel_sig: "".to_string(),
        intel_x509: "".to_string(),
        guardian_eth_pub_keys: recipient_keys
            .iter()
            .map(|k| crate::crypto::eth_keys::eth_pk_to_hex_uncompressed(&k.guardian_public_key))
            .collect(),
        withdrawal_credentials: hex::encode(withdrawal_credentials),
        fork_version: crate::eth2::eth_types::GENESIS_FORK_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_decrypt() {
        let withdrawal_credentials = [1; 32];
        let threshold = 1;
        let (_g_sk, g_pk) = crate::crypto::eth_keys::new_eth_key().unwrap();
        let password = "password".to_string();

        // Validator generates fresh keystore, provisions custody to Guardians, and creates deposit msg
        let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
            guardian_pubkeys: vec![g_pk.clone()],
            withdrawal_credentials: withdrawal_credentials.clone(),
            threshold,
            do_remote_attestation: false,
        };
        let payload = generate_bls_keystore_handler(payload, &password).unwrap();

        // Verify we can decrypt the keystore
        let sk = crate::crypto::bls_keys::fetch_bls_sk_keystore(&payload.bls_pub_key, &password).unwrap();

        // Verify the fields match
        assert_eq!(sk.public_keys().public_key().to_hex(), payload.public_key_set().unwrap().public_key().to_hex());
    }
}
