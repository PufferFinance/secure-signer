use crate::io::remote_attestation::AttestationEvidence;
use crate::{crypto::eth_keys, strip_0x_prefix};
use anyhow::{bail, Result};
use blsttc::PublicKey as BlsPublicKey;
use ecies::PublicKey as EthPublicKey;
use ethers::types::TxHash;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

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

#[derive(Deserialize, Serialize, Debug)]
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
    // TODO: This can be found out from which part ends up being decrypted
    pub guardian_index: usize,
    pub guardian_enclave_public_key: EthPublicKey,
    pub withdrawal_credentials: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ValidateCustodyResponse {
    #[serde(
        serialize_with = "serialize_signature_as_hex",
        deserialize_with = "deserialize_signature_from_hex"
    )]
    pub signature: libsecp256k1::Signature,
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
    pub bls_pub_key: String,
    pub signature: String,
    pub deposit_data_root: TxHash,
    pub bls_enc_priv_key_shares: Vec<String>,
    pub bls_pub_key_shares: Vec<String>,
    pub intel_sig: String,
    pub intel_report: String,
    pub intel_x509: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EigenPodData {
    pub puffer_pool_address: ethers::abi::Address,
    pub eigen_pod_manager_address: ethers::abi::Address,
    pub eigen_pod_beacon_address: ethers::abi::Address,
    pub eigen_pod_proxy_init_code: String,
    pub beacon_proxy_bytecode: String,
    pub pod_account_owners: Vec<ethers::types::Address>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestFreshBlsKeyPayload {
    pub blockhash: String,
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
