use crate::eth_types::{Slot, Epoch, Root, BLSPubkey, from_u64_string, from_bls_pk_hex};
use serde::{Deserialize, Deserializer, Serialize};
use serde::de;
use serde_hex::{SerHex, StrictPfx};

pub fn deserialize_signing_root<'de, D>(deserializer: D) -> Result<Option<Root>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: &str = Deserialize::deserialize(deserializer)?;
    if hex_string.is_empty() {
      return Ok(None);
    }
    let bytes: Root = SerHex::<StrictPfx>::from_hex(&hex_string).expect("bad hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    Ok(Some(array))
}

#[derive(Debug, Deserialize, Serialize)]
/// Specs: https://eips.ethlibrary.io/eip-3076.html
pub struct SlashingProtectionDB {
    pub metadata: SlashingProtectionMetaData,
    pub title: Option<String>,
    pub description: Option<String>,
    pub data: Vec<SlashingProtectionData>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SlashingProtectionMetaData {
    pub interchange_format_version: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Root,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SlashingProtectionData {
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
    pub signed_blocks: Vec<SignedBlockSlots>,
    pub signed_attestations: Vec<SignedAttestationEpochs>,
    pub required: Option<Vec<String>>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_signing_root")]
    pub signing_root: Option<Root>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedAttestationEpochs {
    #[serde(deserialize_with = "from_u64_string")]
    pub source_epoch: Epoch,
    #[serde(deserialize_with = "from_u64_string")]
    pub target_epoch: Epoch,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_signing_root")]
    pub signing_root: Option<Root>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedBlockSlots {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_signing_root")]
    pub signing_root: Option<Root>,
}


#[cfg(test)]
mod test_serde {
    use super::*;
    use anyhow::Result;
    use serde_json;
    use hex;
    use ssz::Encode;

    #[test]
    fn test_serialize() -> Result<()> {
        let raw = r#"
        {
            "metadata": {
              "interchange_format_version": "5",
              "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            },
            "data": [
              {
                "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
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
          }"#;

        let db: SlashingProtectionDB = serde_json::from_str(raw)?;
        assert_eq!(db.metadata.interchange_format_version, "5");
        assert_eq!(hex::encode(db.metadata.genesis_validators_root), "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string());
        assert_eq!(hex::encode(&db.data[0].pubkey.as_ssz_bytes()), "b845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed".to_string());

        // block 0
        assert_eq!(db.data[0].signed_blocks[0].slot, 81952);
        assert_eq!(hex::encode(&db.data[0].signed_blocks[0].signing_root.unwrap()), "4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string());
        
        // block 1
        assert_eq!(db.data[0].signed_blocks[1].slot, 81951);
        assert!(db.data[0].signed_blocks[1].signing_root.is_none());

        // attestation 0
        assert_eq!(db.data[0].signed_attestations[0].source_epoch, 2290);
        assert_eq!(db.data[0].signed_attestations[0].target_epoch, 3007);
        assert_eq!(hex::encode(&db.data[0].signed_attestations[0].signing_root.unwrap()), "587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d".to_string());

        // attestation 1
        assert_eq!(db.data[0].signed_attestations[1].source_epoch, 2290);
        assert_eq!(db.data[0].signed_attestations[1].target_epoch, 3008);
        assert!(db.data[0].signed_attestations[1].signing_root.is_none());
        Ok(())
    }


}