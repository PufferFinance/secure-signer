use crate::{
    crypto::bls_keys::save_bls_key, eth2::eth_types::DepositResponse,
    io::remote_attestation::AttestationEvidence,
};
use anyhow::Result;
use blsttc::{PublicKeySet, PublicKeyShare, SecretKeyShare, SignatureShare};
use ecies::PublicKey as EthPublicKey;
use sha3::Digest;
use ssz::Encode;
pub mod handlers;

#[derive(Clone, Debug)]
pub struct RecipientKeys {
    pub guardian_public_key: EthPublicKey,
    pub secret_key_share: SecretKeyShare,
    pub public_key_share: PublicKeyShare,
}

#[derive(Clone, Debug)]
pub struct EncryptedRecipientKeys {
    pub guardian_public_key: EthPublicKey,
    pub public_key_share: PublicKeyShare,
    pub encrypted_secret_key_share_hex: String,
}

impl RecipientKeys {
    /// ECIES envelope encrypt the BLS secret key share with the recipient ETH public key
    pub fn encrypt_to_recipient(&self) -> Result<EncryptedRecipientKeys> {
        let ct_sk = crate::crypto::eth_keys::envelope_encrypt(
            &self.guardian_public_key,
            &self.secret_key_share.to_bytes(),
        )?;

        Ok(EncryptedRecipientKeys {
            guardian_public_key: self.guardian_public_key,
            public_key_share: self.public_key_share,
            encrypted_secret_key_share_hex: hex::encode(ct_sk),
        })
    }

    /// Return partial BLS signature over the message using BLS secret key share
    pub fn bls_partial_sign<M: AsRef<[u8]>>(&self, message: M) -> SignatureShare {
        self.secret_key_share.sign(message)
    }

    /// Verify partial BLS signature using the known BLS public key share
    pub fn bls_partial_verify<M: AsRef<[u8]>>(
        &self,
        signature: &SignatureShare,
        message: M,
    ) -> bool {
        self.public_key_share.verify(signature, message)
    }
}

pub fn attest_fresh_bls_key(
    withdrawal_credentials: [u8; 32],
    guardian_public_keys: Vec<EthPublicKey>,
    threshold: usize,
    fork_version: [u8; 4],
) -> Result<super::types::BlsKeygenPayload> {
    // Generate a SecretKeySet where t + 1 signature shares can be combined into a full signature. attest_fresh_bls_key() function assumes `threshold = t + 1`, so we must pass new_bls_key(t=threshold - 1)
    let secret_key_set = crate::crypto::bls_keys::new_bls_key(threshold - 1);

    // Shard the key into `n` keyshares
    let n = guardian_public_keys.len();
    let key_shares = crate::crypto::bls_keys::distribute_key_shares(&secret_key_set, n);

    // Encrypt the shares to using guardian pubkeys
    let mut recipient_keys: Vec<EncryptedRecipientKeys> = Vec::new();
    for (g_pk, (sk_share, pk_share)) in guardian_public_keys.into_iter().zip(key_shares.into_iter())
    {
        let k = RecipientKeys {
            guardian_public_key: g_pk,
            secret_key_share: sk_share,
            public_key_share: pk_share,
        }
        .encrypt_to_recipient()?;
        recipient_keys.push(k);
    }

    // get validator aggregate public key
    let validator_pubkey = secret_key_set.public_keys().public_key();

    // save validator private key to enclave
    save_bls_key(&secret_key_set)?;

    // sign DepositMessage to deposit 32 ETH to beacon deposit contract
    let deposit_message = crate::eth2::eth_types::DepositMessage {
        pubkey: validator_pubkey.to_bytes().to_vec().into(),
        withdrawal_credentials,
        amount: crate::constants::FULL_DEPOSIT_AMOUNT,
    };

    let deposit_resp = crate::eth2::eth_signing::get_deposit_signature(
        validator_pubkey.to_hex(),
        deposit_message,
        fork_version,
    )?;

    // build remote attestation payload
    let payload = build_validator_remote_attestation_payload(
        secret_key_set.public_keys().clone(),
        deposit_resp.clone(),
        recipient_keys.clone(),
    )?;

    // do remote attestation
    let evidence = AttestationEvidence::new(&payload)?;

    dbg!(Ok(super::types::BlsKeygenPayload {
        bls_pub_key_set: hex::encode(secret_key_set.public_keys().to_bytes()),
        bls_pub_key: validator_pubkey.to_hex(),
        signature: deposit_resp.signature,
        deposit_data_root: deposit_resp.deposit_data_root,
        bls_enc_priv_key_shares: recipient_keys
            .into_iter()
            .map(|encrypted_key| encrypted_key.encrypted_secret_key_share_hex)
            .collect(),
        intel_report: evidence.raw_report,
        intel_sig: evidence.signed_report,
        intel_x509: evidence.signing_cert,
    }))
}

pub fn build_validator_remote_attestation_payload(
    validator_pk_set: PublicKeySet,
    deposit: DepositResponse,
    shares: Vec<EncryptedRecipientKeys>,
) -> Result<Vec<u8>> {
    let mut hasher = sha3::Keccak256::new();

    // blsPubKeySet
    hasher.update(validator_pk_set.to_bytes());

    // blsPubKey
    hasher.update(validator_pk_set.public_key().to_bytes());

    // signature
    hasher.update(hex::decode(deposit.signature)?);

    // depositDataRoot
    hasher.update(hex::decode(deposit.deposit_data_root)?);

    for share in shares.iter() {
        // blsEncryptedPrivKeyShares
        let decoded_bytes = hex::decode(&share.encrypted_secret_key_share_hex)?;
        hasher.update(&decoded_bytes);

        // blsPubKeyShares
        hasher.update(&share.public_key_share.to_bytes());

        // guardianPubKeys
        hasher.update(&share.guardian_public_key.serialize());
    }

    // threshold
    hasher.update(validator_pk_set.threshold().as_ssz_bytes());

    let digest: [u8; 32] = hasher.finalize().into();

    Ok(digest.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::eth2::eth_types::Version;

    use super::*;
    use ecies::{PublicKey as EthPublicKey, SecretKey as EthSecretKey};

    #[test]
    fn test() {
        let n: usize = 4;
        let withdrawal_credentials: [u8; 32] = [0; 32];

        // Setup Guardians
        let mut g_pks: Vec<EthPublicKey> = Vec::new();
        let mut g_sks: Vec<EthSecretKey> = Vec::new();
        for _ in 0..n {
            let (sk, pk) = crate::crypto::eth_keys::new_eth_key().unwrap();
            g_pks.push(pk);
            g_sks.push(sk);
        }

        let threshold = 3; // for threshold/N
        let secret_key_set = crate::crypto::bls_keys::new_bls_key(threshold - 1);
        let validator_pk_set = secret_key_set.public_keys();
        let validator_pk = validator_pk_set.public_key();
        // let validator_private_key = secret_key_set.secret_key();
        let pk_hex: String = validator_pk_set.public_key().to_hex();

        // Shard the key into `n` keyshares
        let key_shares = crate::crypto::bls_keys::distribute_key_shares(&secret_key_set, n);

        // Encrypt the shares to using guardian pubkeys
        let recipent_keys: Vec<EncryptedRecipientKeys> = g_pks
            .iter()
            .zip(key_shares.into_iter())
            .map(
                |(guardian_public_key, (secret_key_share, public_key_share))| {
                    dbg!(&hex::encode(secret_key_share.to_bytes()));
                    dbg!(&hex::encode(public_key_share.to_bytes()));
                    RecipientKeys {
                        guardian_public_key: guardian_public_key.clone(),
                        secret_key_share,
                        public_key_share,
                    }
                    .encrypt_to_recipient()
                    .unwrap()
                },
            )
            .collect();

        // save validator private key to enclave
        save_bls_key(&secret_key_set).unwrap();

        // sign DepositMessage to deposit 32 ETH to beacon deposit contract
        let deposit_message = crate::eth2::eth_types::DepositMessage {
            pubkey: validator_pk.to_bytes().to_vec().into(),
            withdrawal_credentials,
            amount: crate::constants::FULL_DEPOSIT_AMOUNT,
        };

        let deposit_resp = crate::eth2::eth_signing::get_deposit_signature(
            pk_hex,
            deposit_message,
            Version::default(),
        )
        .unwrap();

        dbg!(&deposit_resp);

        let payload = build_validator_remote_attestation_payload(
            validator_pk_set.clone(),
            deposit_resp.clone(),
            recipent_keys.clone(),
        )
        .unwrap();

        dbg!(hex::encode(payload));

        // skip remote attestation for local test

        // Verify we can decrypt each encrypted keyshare
        let mut sk_shares: Vec<SecretKeyShare> = Vec::new();
        let mut pk_shares: Vec<PublicKeyShare> = Vec::new();
        let mut sig_shares: Vec<SignatureShare> = Vec::new();
        let msg = b"hello puffer";
        for i in 0..n {
            let eth_sk = g_sks[i];
            let pk_share = recipent_keys[i].public_key_share.clone();
            let enc_sk_bytes =
                hex::decode(recipent_keys[i].clone().encrypted_secret_key_share_hex).unwrap();

            // decrypt guardian's sk share
            let sk_bytes =
                crate::crypto::eth_keys::envelope_decrypt(&eth_sk, &enc_sk_bytes).unwrap();
            let sk_share =
                blsttc::SecretKeyShare::from_bytes(sk_bytes[..].try_into().unwrap()).unwrap();
            dbg!(&hex::encode(sk_share.to_bytes()));
            dbg!(&hex::encode(pk_share.to_bytes()));

            // sign a test msg using keyshare
            let signature: SignatureShare = sk_share.sign(&msg);

            // verify it with the guardian's pubkey share
            assert!(pk_share.verify(&signature, &msg));

            sig_shares.push(signature);
            sk_shares.push(sk_share);
            pk_shares.push(pk_share);
        }

        // verify the validator pubkey is from this pk_set
        assert_eq!(
            validator_pk_set.public_key().to_hex(),
            validator_pk.to_hex()
        );

        // verify each pk_share derived from pk_set
        for i in 0..n {
            let pk_share = recipent_keys[i].public_key_share.clone();
            assert_eq!(
                hex::encode(pk_share.to_bytes()),
                hex::encode(validator_pk_set.public_key_share(i).to_bytes())
            );
        }

        // verify sk_share is valid
        for i in 0..n {
            let sk_share = sk_shares[i].clone();

            assert_eq!(
                hex::encode(sk_share.public_key_share().to_bytes()),
                hex::encode(validator_pk_set.public_key_share(i).to_bytes())
            );
        }

        // Verify the signatures aggregate
        let rec_sig =
            crate::crypto::bls_keys::aggregate_signature_shares(&validator_pk_set, &sig_shares)
                .unwrap();
        assert!(validator_pk.verify(&rec_sig, msg));
    }
}
