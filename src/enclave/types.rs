use crate::io::remote_attestation::AttestationEvidence;
use crate::{crypto::eth_keys, strip_0x_prefix};
use anyhow::{bail, Result};
use blsttc::{PublicKey as BlsPublicKey, PublicKeySet};
use ecies::{PublicKey as EthPublicKey, SecretKey as EthSecretKey};
use ethers::types::TxHash;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct KeyGenResponse {
    pub pk_hex: String,
    pub evidence: AttestationEvidence,
}

impl KeyGenResponse {
    pub fn from_eth_key(pk: EthPublicKey, evidence: AttestationEvidence) -> Self {
        let pk: String = strip_0x_prefix!(hex::encode(pk.serialize())); // uncompressed
        KeyGenResponse {
            pk_hex: format!("0x{}", pk),
            evidence,
        }
    }

    pub fn from_bls_key(pk: BlsPublicKey, evidence: AttestationEvidence) -> Self {
        KeyGenResponse {
            pk_hex: format!("0x{}", &pk.to_hex()),
            evidence,
        }
    }

    pub fn validate_eth_ra(&self, mrenclave: &String) -> Result<EthPublicKey> {
        // Verify the report is valid
        self.evidence.verify_intel_signing_certificate()?;

        // Verify the MRENCLAVE measurement is valid
        let mrenclave: String = strip_0x_prefix!(mrenclave);
        let got_mrenclave = self.evidence.get_mrenclave()?;
        if mrenclave != got_mrenclave {
            bail!("Received MRENCLAVE {got_mrenclave} does not match expected {mrenclave}")
        }

        // Get the expected public key from payload
        let pk = eth_keys::eth_pk_from_hex(&self.pk_hex)?;

        // Read the 64B payload from RA report
        let got_payload: [u8; 64] = self.evidence.get_report_data()?;

        // Verify the first ETH_COMPRESSED_PK_BYTES of report contains the expected ETH comporessed public key
        // TODO: Ideally this should be uncompressed
        if &got_payload[0..crate::constants::ETH_COMPRESSED_PK_BYTES] != pk.serialize_compressed() {
            bail!("Remote attestation payload does not match the expected")
        }
        Ok(pk)
    }

    pub fn validate_bls_ra(&self, mrenclave: &String) -> Result<BlsPublicKey> {
        // Verify the report is valid
        self.evidence.verify_intel_signing_certificate()?;

        // Verify the MRENCLAVE measurement is valid
        let mrenclave: String = strip_0x_prefix!(mrenclave);
        let got_mrenclave = self.evidence.get_mrenclave()?;
        if mrenclave != got_mrenclave {
            bail!("Received MRENCLAVE {got_mrenclave} does not match expected {mrenclave}")
        }

        // Verify the payload
        let pk_hex: String = strip_0x_prefix!(&self.pk_hex);
        let pk = BlsPublicKey::from_hex(&pk_hex)?;

        // Read the 64B payload from RA report
        let got_payload: [u8; 64] = self.evidence.get_report_data()?;

        // Verify the first BLS_PUB_KEY_BYTES of report contains the expected BLS comporessed public key
        if &got_payload[0..crate::constants::BLS_PUB_KEY_BYTES] != pk.to_bytes() {
            bail!("Remote attestation payload does not match the expected")
        }
        Ok(pk)
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys
            .iter()
            .map(|pk| {
                // Prepend leading 0x if needed
                let pubkey = match pk[0..2].into() {
                    "0x" => pk.to_string(),
                    _ => "0x".to_owned() + &pk.to_string(),
                };
                ListKeysResponseInner {
                    pubkey: pubkey.into(),
                }
            })
            .collect();

        ListKeysResponse { data: inners }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureResponse {
    pub signature: String,
}

impl SignatureResponse {
    pub fn new(sig: &[u8]) -> Self {
        SignatureResponse {
            signature: format!("0x{}", hex::encode(sig)),
        }
    }

    pub fn to_ssz_bytes(&self) -> Result<crate::eth2::eth_types::BLSSignature> {
        let sig_stripped: String = strip_0x_prefix!(self.signature.clone());
        let sig_bytes = hex::decode(sig_stripped)?;
        Ok(crate::eth2::eth_types::BLSSignature::from(sig_bytes))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ValidateCustodyRequest {
    pub keygen_payload: BlsKeygenPayload,
    pub guardian_enclave_public_key: EthPublicKey,
    pub mrenclave: String,
    pub mrsigner: String,
    pub verify_remote_attestation: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ValidateCustodyResponse {
    pub enclave_signature: String,
    pub bls_pub_key: String,
    pub withdrawal_credentials: String,
    pub deposit_signature: String,
    pub deposit_data_root: String,
}

fn serialize_signature_as_hex<S>(
    signature: &libsecp256k1::Signature,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = signature.serialize();
    let hex_string = hex::encode(bytes);
    serializer.serialize_str(&hex_string)
}

fn deserialize_signature_from_hex<'de, D>(
    deserializer: D,
) -> Result<libsecp256k1::Signature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_string: String = Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;

    let signature =
        libsecp256k1::Signature::parse_standard_slice(&bytes).map_err(serde::de::Error::custom)?;

    Ok(signature)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlsKeygenPayload {
    pub bls_pub_key_set: String,
    pub bls_pub_key: String,
    pub signature: String,
    pub deposit_data_root: String,
    pub bls_enc_priv_key_shares: Vec<String>,
    pub intel_sig: String,
    pub intel_report: String,
    pub intel_x509: String,
    pub guardian_eth_pub_keys: Vec<String>,
    pub withdrawal_credentials: String,
    pub fork_version: crate::eth2::eth_types::Version,
}

impl BlsKeygenPayload {
    pub fn public_key_set(&self) -> Result<PublicKeySet> {
        let sanitized: String = crate::strip_0x_prefix!(&self.bls_pub_key_set);
        Ok(PublicKeySet::from_bytes(hex::decode(sanitized)?)?)
    }

    pub fn withdrawal_credentials(&self) -> Result<[u8; 32]> {
        let sanitized: String = crate::strip_0x_prefix!(&self.withdrawal_credentials);
        let mut wc: [u8; crate::constants::WITHDRAWAL_CREDENTIALS_BYTES] =
            [0; crate::constants::WITHDRAWAL_CREDENTIALS_BYTES];
        let wc_bytes = hex::decode(&sanitized)?;
        if wc_bytes.len() != crate::constants::WITHDRAWAL_CREDENTIALS_BYTES {
            bail!("Invalid  withdrawal_credentials")
        }
        wc.copy_from_slice(&wc_bytes);
        Ok(wc)
    }

    pub fn signature(&self) -> Result<blsttc::Signature> {
        let sanitized: String = crate::strip_0x_prefix!(&self.signature);
        let mut sig_bytes: [u8; crate::constants::BLS_SIG_BYTES] =
            [0; crate::constants::BLS_SIG_BYTES];
        sig_bytes.copy_from_slice(&hex::decode(&sanitized)?);
        Ok(blsttc::Signature::from_bytes(sig_bytes)?)
    }

    pub fn deposit_message_root(&self) -> Result<crate::eth2::eth_types::Root> {
        let pk_set = self.public_key_set()?;
        let withdrawal_credentials = self.withdrawal_credentials()?;
        let deposit_message = crate::eth2::eth_types::DepositMessage {
            pubkey: pk_set.public_key().to_bytes().to_vec().into(),
            withdrawal_credentials: withdrawal_credentials.clone(),
            amount: crate::constants::FULL_DEPOSIT_AMOUNT,
        };
        let domain = crate::eth2::eth_signing::compute_domain(
            crate::eth2::eth_types::DOMAIN_DEPOSIT,
            Some(self.fork_version.clone()),
            None,
        );
        Ok(crate::eth2::eth_signing::compute_signing_root(
            deposit_message.clone(),
            domain,
        ))
    }

    pub fn deposit_data_root(&self) -> Result<crate::eth2::eth_types::Root> {
        let pk_set = self.public_key_set()?;
        let deposit_data = crate::eth2::eth_types::DepositData {
            pubkey: pk_set.public_key().to_bytes().to_vec().into(),
            withdrawal_credentials: self.withdrawal_credentials()?,
            amount: crate::constants::FULL_DEPOSIT_AMOUNT,
            signature: self.signature()?.to_bytes().to_vec().into(),
        };
        Ok(deposit_data.tree_hash_root().to_fixed_bytes())
    }

    pub fn verify_public_keys_match(&self) -> Result<bool> {
        let pk_set = self.public_key_set()?;
        let exp_pk_hex: String = crate::strip_0x_prefix!(&self.bls_pub_key);
        Ok(pk_set.public_key().to_hex() == exp_pk_hex)
    }

    pub fn decrypt_sk_share(
        &self,
        share_index: usize,
        guardian_enclave_sk: &EthSecretKey,
    ) -> Result<blsttc::SecretKeyShare> {
        let sanitized_enc_sk_share: String = match self.bls_enc_priv_key_shares.get(share_index) {
            Some(s) => crate::strip_0x_prefix!(s),
            None => bail!("bad share_index to read from bls_enc_priv_key_shares"),
        };
        let enc_sk_bytes = hex::decode(&sanitized_enc_sk_share)?;
        let sk_bytes =
            crate::crypto::eth_keys::envelope_decrypt(&guardian_enclave_sk, &enc_sk_bytes)?;
        Ok(blsttc::SecretKeyShare::from_bytes(
            sk_bytes[..].try_into()?,
        )?)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignExitRequest {
    pub bls_pub_key_set: String,
    pub guardian_index: u64,
    pub validator_index: u64,
    pub fork_info: crate::eth2::eth_types::ForkInfo,
}

impl SignExitRequest {
    pub fn public_key_set(&self) -> Result<PublicKeySet> {
        let sanitized: String = crate::strip_0x_prefix!(&self.bls_pub_key_set);
        Ok(PublicKeySet::from_bytes(hex::decode(sanitized)?)?)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignExitResponse {
    pub signature: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestFreshBlsKeyPayload {
    #[serde(
        serialize_with = "serialize_pubkeys_hex",
        deserialize_with = "deserialize_pubkeys_from_hex"
    )]
    pub guardian_pubkeys: Vec<EthPublicKey>,
    #[serde(
        serialize_with = "serialize_as_32_bytes_array",
        deserialize_with = "deserialize_32_bytes_from_hex"
    )]
    pub withdrawal_credentials: [u8; 32],
    pub threshold: usize,
    pub fork_version: crate::eth2::eth_types::Version,
    pub do_remote_attestation: bool,
}

fn serialize_pubkeys_hex<S>(pubkeys: &[EthPublicKey], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_strings: Vec<String> = pubkeys
        .iter()
        .map(|pubkey| hex::encode(&pubkey.serialize()))
        .collect();

    let mut seq = serializer.serialize_seq(Some(hex_strings.len()))?;
    for hex_string in hex_strings {
        seq.serialize_element(&hex_string)?;
    }
    seq.end()
}
fn deserialize_pubkeys_from_hex<'de, D>(deserializer: D) -> Result<Vec<EthPublicKey>, D::Error>
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

fn serialize_as_32_bytes_array<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_str = hex::encode(data);
    serializer.serialize_str(&hex_str)
}

fn deserialize_32_bytes_from_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> serde::de::Visitor<'de> for HexVisitor {
        type Value = [u8; 32];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string representing a 32-byte array in hexadecimal format")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let bytes = hex::decode(value).map_err(E::custom)?;
            if bytes.len() != 32 {
                return Err(E::custom(format!("Expected 32 bytes, got {}", bytes.len())));
            }
            let mut array = [0; 32];
            array.copy_from_slice(&bytes);
            Ok(array)
        }
    }

    deserializer.deserialize_str(HexVisitor)
}
