use crate::{
    crypto::bls_keys::save_bls_key,
    enclave::{get_withdrawal_address, BLSKeygenPayload},
    io::remote_attestation::AttestationEvidence,
};
use anyhow::Result;
use blsttc::{PublicKeyShare, SecretKeyShare, SignatureShare};
use bytes::Bytes;
use ecies::PublicKey as EthPublicKey;
use sha3::Digest;
use ssz::Encode;
use tree_hash::TreeHash;

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
    block_hash: Bytes,
    eigen_pod_data: crate::enclave::EigenPodData,
    guardian_public_keys: Vec<EthPublicKey>,
    threshold: usize,
    fork_version: [u8; 4],
) -> Result<BLSKeygenPayload> {
    let threshold = threshold + 1;

    let amount_of_shares = guardian_public_keys.len();

    // # generate N keyshares with M/N signature threshold
    let secret_key_set = crate::crypto::bls_keys::new_bls_key(threshold);

    let key_shares =
        crate::crypto::bls_keys::distribute_key_shares(&secret_key_set, amount_of_shares);
    let recipent_keys: Vec<EncryptedRecipientKeys> = guardian_public_keys
        .iter()
        .zip(key_shares.into_iter())
        .map(
            |(guardian_public_key, (secret_key_share, public_key_share))| {
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

    // # get validator public key
    let validator_pubkey = secret_key_set.public_keys().public_key();

    // # get validator private key
    let validator_private_key = secret_key_set.secret_key();

    // # save validator private key to enclave
    save_bls_key(&secret_key_set).unwrap();

    // ## --- This will be needed later ---
    let mut hasher = sha3::Sha3_256::new();
    // change to pool
    hasher.update(validator_pubkey.to_bytes());
    // # compute deterministic EigenPod address

    let withdrawal_credentials = crate::enclave::get_withdrawal_address(&eigen_pod_data);

    // # sign a DepositMessage to deposit 32 ETH to beacon deposit contract
    let deposit_message = crate::eth2::eth_types::DepositMessage {
        pubkey: hex::decode(validator_pubkey.to_hex())?.into(),
        withdrawal_credentials,
        amount: 32,
    };

    let domain = crate::eth2::eth_signing::compute_domain(
        crate::eth2::eth_types::DOMAIN_DEPOSIT,
        Some(fork_version),
        None,
    );

    let root = crate::eth2::eth_signing::compute_signing_root(deposit_message, domain);
    let signature = validator_private_key.sign(root);

    //DepositData(bls_pk, withdrawal_credentials, bond, p["signature"]).hash_tree_root()
    let deposit_data_root = crate::eth2::eth_types::DepositData {
        pubkey: hex::decode(validator_pubkey.to_hex())?.into(),
        withdrawal_credentials: get_withdrawal_address(&eigen_pod_data),
        amount: 32,
        signature: <_>::from(signature.to_bytes().to_vec()),
    }
    .tree_hash_root();

    // # do remote attestation
    let mut hasher = sha3::Keccak256::new();
    hasher.update(validator_pubkey.to_bytes());
    hasher.update(secret_key_set.public_keys().to_bytes());
    hasher.update(block_hash);
    hasher.update(threshold.as_ssz_bytes());
    let encoded: Bytes = ethers::abi::encode(
        &guardian_public_keys
            .into_iter()
            .map(|x| ethers::abi::Token::Bytes(x.serialize().to_vec()))
            .collect::<Vec<ethers::abi::Token>>(),
    )
    .into();
    hasher.update(encoded);
    let digest_bytes = hasher.finalize();

    let evidence = AttestationEvidence::new(&digest_bytes)?;

    Ok(BLSKeygenPayload {
        bls_pub_key: validator_pubkey.to_hex(),
        signature: hex::encode(signature.to_bytes()),
        deposit_data_root,
        bls_enc_priv_key_shares: recipent_keys
            .iter()
            .map(|encrypted_key| encrypted_key.encrypted_secret_key_share_hex.clone())
            .collect(),
        bls_pub_key_shares: recipent_keys
            .iter()
            .map(|encrypted_key| hex::encode(encrypted_key.public_key_share.to_bytes()))
            .collect(),
        intel_report: evidence.raw_report,
        intel_sig: evidence.signed_report,
        intel_x509: evidence.signing_cert,
    })
}
