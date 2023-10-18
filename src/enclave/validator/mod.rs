use crate::{crypto::bls_keys::save_bls_key, io::remote_attestation::AttestationEvidence};
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

    //     pub fn guardian_public_keys(&self) -> &Vec<PublicKeyShare> {
    //         self.guardian_public_keys().iter()
    // j
    //     }
}

pub fn attest_fresh_bls_key(
    withdrawal_credentials: [u8; 32],
    guardian_public_keys: Vec<EthPublicKey>,
    threshold: usize,
    fork_version: [u8; 4],
    do_remote_attestation: bool,
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
    let (signature, deposit_data_root) = crate::eth2::eth_signing::sign_full_deposit(
        &secret_key_set,
        withdrawal_credentials.clone(),
        fork_version,
    )?;

    // build remote attestation payload
    let payload = crate::enclave::build_validator_remote_attestation_payload(
        secret_key_set.public_keys().clone(),
        &signature,
        &deposit_data_root,
        recipient_keys
            .iter()
            .map(|k| k.encrypted_secret_key_share_hex.clone())
            .collect(),
        recipient_keys
            .iter()
            .map(|k| k.guardian_public_key.clone())
            .collect(),
    )?;

    // do remote attestation
    let evidence = if do_remote_attestation {
        AttestationEvidence::new(&payload)?
    } else {
        AttestationEvidence::default()
    };

    dbg!(Ok(super::types::BlsKeygenPayload {
        bls_pub_key_set: hex::encode(secret_key_set.public_keys().to_bytes()),
        bls_pub_key: validator_pubkey.to_hex(),
        signature: hex::encode(&signature[..]),
        deposit_data_root: hex::encode(deposit_data_root),
        bls_enc_priv_key_shares: recipient_keys
            .iter()
            .map(|encrypted_key| encrypted_key.encrypted_secret_key_share_hex.clone())
            .collect(),
        intel_report: evidence.raw_report,
        intel_sig: evidence.signed_report,
        intel_x509: evidence.signing_cert,
        guardian_eth_pub_keys: recipient_keys
            .iter()
            .map(|k| crate::crypto::eth_keys::eth_pk_to_hex_uncompressed(&k.guardian_public_key))
            .collect(),
        withdrawal_credentials: hex::encode(withdrawal_credentials),
    }))
}

// pub fn build_validator_remote_attestation_payload(
//     validator_pk_set: PublicKeySet,
//     signature: &crate::eth2::eth_types::BLSSignature,
//     deposit_data_root: &crate::eth2::eth_types::Root,
//     enc_sk_shares: Vec<String>,
//     guardian_pks: Vec<EthPublicKey>,
// ) -> Result<Vec<u8>> {
//     let mut hasher = sha3::Keccak256::new();

//     // blsPubKeySet
//     hasher.update(validator_pk_set.to_bytes());

//     // blsPubKey
//     hasher.update(validator_pk_set.public_key().to_bytes());

//     // signature
//     hasher.update(signature.as_ssz_bytes());

//     // depositDataRoot
//     hasher.update(deposit_data_root);

//     for (i, (sk_share, g_pk)) in enc_sk_shares.iter().zip(guardian_pks.iter()).enumerate() {
//         // blsEncPrivKeyShares
//         hasher.update(hex::decode(&sk_share)?);

//         // blsPubKeyShares
//         hasher.update(&validator_pk_set.public_key_share(i).to_bytes());

//         // guardianPubKeys
//         hasher.update(&g_pk.serialize());
//     }

//     // threshold
//     hasher.update(validator_pk_set.threshold().as_ssz_bytes());

//     let digest: [u8; 32] = hasher.finalize().into();

//     Ok(digest.to_vec())
// }

#[cfg(test)]
mod tests {
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

        // Shard the key into `n` keyshares
        let key_shares = crate::crypto::bls_keys::distribute_key_shares(&secret_key_set, n);

        // Encrypt the shares to using guardian pubkeys
        let recipient_keys: Vec<EncryptedRecipientKeys> = g_pks
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
        let (signature, deposit_data_root) = crate::eth2::eth_signing::sign_full_deposit(
            &secret_key_set,
            withdrawal_credentials,
            crate::eth2::eth_types::Version::default(),
        )
        .unwrap();

        let payload = crate::enclave::build_validator_remote_attestation_payload(
            secret_key_set.public_keys().clone(),
            &signature,
            &deposit_data_root,
            recipient_keys
                .iter()
                .map(|k| k.encrypted_secret_key_share_hex.clone())
                .collect(),
            recipient_keys
                .iter()
                .map(|k| k.guardian_public_key.clone())
                .collect(),
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
            let pk_share = recipient_keys[i].public_key_share.clone();
            let enc_sk_bytes =
                hex::decode(recipient_keys[i].clone().encrypted_secret_key_share_hex).unwrap();

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
            let pk_share = recipient_keys[i].public_key_share.clone();
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
