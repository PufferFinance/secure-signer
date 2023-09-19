use crate::{
    crypto::bls_keys::save_bls_key, enclave::get_withdrawal_address,
    io::remote_attestation::AttestationEvidence, strip_0x_prefix,
};
use anyhow::Result;
use blsttc::{PublicKeyShare, SecretKeyShare, SignatureShare};
use bytes::Bytes;
use ecies::PublicKey as EthPublicKey;
use sha3::Digest;
use ssz::Encode;
use tree_hash::TreeHash;
pub mod handlers;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestFreshEthKeyPayload {
    eigen_pod_data: super::types::EigenPodData,
    blockhash: String,
    #[serde(
        serialize_with = "serialize_as_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    guardian_pubkeys: Vec<EthPublicKey>,
    threshold: usize,
}

fn serialize_as_hex<S>(pubkeys: &[EthPublicKey], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_strings: Vec<String> = pubkeys
        .iter()
        .map(|pubkey| hex::encode(&pubkey.serialize()))
        .collect();

    serializer.serialize_str(&hex_strings.join(","))
}
fn deserialize_from_hex<'de, D>(deserializer: D) -> Result<Vec<EthPublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> serde::de::Visitor<'de> for HexVisitor {
        type Value = Vec<EthPublicKey>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of hex strings")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let mut pubkeys = Vec::new();
            while let Some(hex_string) = seq.next_element::<String>()? {
                let hex_string: String = strip_0x_prefix!(hex_string);
                let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
                let pubkey =
                    EthPublicKey::parse_slice(&bytes, None).map_err(serde::de::Error::custom)?;
                pubkeys.push(pubkey);
            }
            Ok(pubkeys)
        }
    }

    deserializer.deserialize_seq(HexVisitor)
}

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
    block_hash: String,
    eigen_pod_data: super::types::EigenPodData,
    guardian_public_keys: Vec<EthPublicKey>,
    threshold: usize,
    fork_version: [u8; 4],
) -> Result<super::types::BlsKeygenPayload> {
    let block_hash: String = strip_0x_prefix!(block_hash);
    let block_hash = hex::decode(block_hash)?;
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

    let withdrawal_credentials = crate::enclave::get_withdrawal_address(&eigen_pod_data)?;

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
        withdrawal_credentials: get_withdrawal_address(&eigen_pod_data)?,
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

    Ok(super::types::BlsKeygenPayload {
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

#[cfg(test)]
mod tests {
    use ecies::PublicKey as EthPublicKey;

    #[test]
    fn test() {
        let secret = ecies::SecretKey::random(&mut rand::rngs::OsRng {});
        let key: EthPublicKey = EthPublicKey::from_secret_key(&secret);
        dbg!(hex::encode(key.serialize()));
        // dbg!(base64::decode(serde_json::to_string(&key)));
    }
}
