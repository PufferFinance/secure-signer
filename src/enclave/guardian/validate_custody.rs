use anyhow::{anyhow, Result};
use ecies::PublicKey as EthPublicKey;
use ethers::abi::Address;
use libsecp256k1::SecretKey as EthSecretKey;
use sha3::Digest;
use ssz_types::FixedVector;
use tree_hash::TreeHash;

use crate::enclave::BLSKeygenPayload;

pub fn generate_signature(
    keygen_payload: BLSKeygenPayload,
    // we can iterate over the guardian public keys to find the index (?)
    guardian_index: usize,
    guardian_enclave_public_key: EthPublicKey,
    eigen_pod_data: crate::enclave::EigenPodData,
) -> Result<(libsecp256k1::Signature, libsecp256k1::Message, bool)> {
    let validator_public_key_hex = keygen_payload.bls_pub_key.clone();
    let Ok(guardian_enclave_private_key) = crate::crypto::eth_keys::fetch_eth_key(
        &crate::crypto::eth_keys::eth_pk_to_hex(&guardian_enclave_public_key),
    ) else {
        return Err(anyhow!("Could not fetch guardian enclave public key"));
    };

    let has_custody = match verify_custody(
        guardian_enclave_private_key,
        &keygen_payload,
        guardian_index,
    ) {
        Err(_) | Ok(false) => false,
        Ok(true) => true,
    };

    let withdrawal_credentials = crate::enclave::calculate_withdraw_address(eigen_pod_data);
    // The leading byte is value one
    let mut withdrawal_credentials_zero_padded = [0u8; 32];
    withdrawal_credentials_zero_padded[12..32].copy_from_slice(&withdrawal_credentials[..]);

    check_data_root(
        &validator_public_key_hex,
        withdrawal_credentials_zero_padded,
        &keygen_payload.signature,
        &keygen_payload.deposit_data_root,
    )?;

    // # at this point we have verified:
    // # 1. if this enclave got custody of a private keyshare
    // # 2. the public keyshares is part of the aggregate
    // # 3. the validator submitted a valid signed deposit msg
    // # 4. the validator build a valid depositDataRoot

    // # sign final message
    let (signature, message) = calculate_signature(
        &guardian_enclave_public_key,
        &validator_public_key_hex,
        &guardian_enclave_private_key,
        &withdrawal_credentials,
        keygen_payload.signature,
        keygen_payload.deposit_data_root,
    )?;

    // We only need the signature
    Ok((signature, message, has_custody))
}

fn check_data_root(
    validator_public_key_hex: &str,
    withdrawal_credentials_zero_padded: [u8; 32],
    signature: &str,
    deposit_data_root: &ethers::types::TxHash,
) -> Result<()> {
    let signature: FixedVector<u8, _> = hex::decode(signature)?.into();
    let deposit_data = crate::eth2::eth_types::DepositData {
        pubkey: hex::decode(validator_public_key_hex.clone())?.into(),
        withdrawal_credentials: withdrawal_credentials_zero_padded,
        amount: 32,
        signature: signature.clone(),
    };

    if deposit_data.tree_hash_root().to_fixed_bytes() != deposit_data_root.to_fixed_bytes() {
        return Err(anyhow!("The deposit data root does not match"));
    };
    Ok(())
}

fn verify_custody(
    guardian_enclave_secret_key: EthSecretKey,
    keygen_payload: &BLSKeygenPayload,
    guardian_index: usize,
) -> Result<bool> {
    // Load key
    let validator_secret_key_shard = keygen_payload
        .bls_enc_priv_key_shares
        .get(guardian_index)
        .unwrap();

    let secret_key_shard_bytes = hex::decode(validator_secret_key_shard)?;
    dbg!(&secret_key_shard_bytes);

    let secret_key_shard = dbg!(crate::crypto::eth_keys::envelope_decrypt(
        &guardian_enclave_secret_key,
        &secret_key_shard_bytes,
    ))?;
    // # sign a random test msg (e.g., hash of inputs) using keyshare
    let secret_key_shard =
        blsttc::SecretKeyShare::from_bytes(secret_key_shard[..].try_into().unwrap())?;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(guardian_enclave_secret_key.serialize());
    let msg_to_be_signed = hasher.finalize();
    let signature = secret_key_shard.sign(&msg_to_be_signed);

    let validator_public_key_shard = keygen_payload
        .bls_pub_key_shares
        .get(guardian_index)
        .unwrap();

    let public_key_shard_bytes = hex::decode(validator_public_key_shard)?;

    let public_key_share =
        blsttc::PublicKeyShare::from_bytes(public_key_shard_bytes[..].try_into().unwrap())?;

    Ok(public_key_share.verify(&signature, &msg_to_be_signed))
}

fn calculate_signature(
    guardian_enclave_public_key: &EthPublicKey,
    validator_public_key_hex: &str,
    guardian_enclave_private_key: &EthSecretKey,
    withdrawal_credentials: &Address,
    signature: String,
    deposit_data_root: ethers::types::TxHash,
) -> Result<(libsecp256k1::Signature, libsecp256k1::Message)> {
    let signature: Vec<u8> = hex::decode(signature)?;

    let enclave_secret_key = crate::crypto::eth_keys::fetch_eth_key(
        &crate::crypto::eth_keys::eth_pk_to_hex(guardian_enclave_public_key),
    )?;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(hex::decode(validator_public_key_hex)?);
    hasher.update(guardian_enclave_private_key.serialize());
    hasher.update(withdrawal_credentials);
    hasher.update(signature.to_vec());
    hasher.update(deposit_data_root.as_bytes());
    let msg_to_be_signed = hasher.finalize();

    crate::crypto::eth_keys::sign_message(&msg_to_be_signed, &enclave_secret_key)
}
