use crate::eth_types::{Slot, Epoch, Root, BLSPubkey, from_u64_string, from_bls_pk_hex};
use serde::{Deserialize, Deserializer, Serialize};
use serde::de;
use serde_hex::{SerHex, StrictPfx};
use anyhow::{Result, bail};
use std::fs;
use std::path::PathBuf;

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
    pub signed_blocks: Vec<SignedBlockSlot>,
    pub signed_attestations: Vec<SignedAttestationEpochs>,
}

impl SlashingProtectionData {
  pub fn new(pubkey: BLSPubkey) -> Self {
    SlashingProtectionData {
      pubkey,
      signed_blocks: vec![],
      signed_attestations: vec![],
    }
  }

  fn get_latest_signed_block_slot(&self) -> Slot {
    match self.signed_blocks.last() {
      None => 0,
      Some(b) => b.slot
    }
  }

  /// If the SlashingProtectionDB is growable, append the new block, otherwise
  /// overwrite the 0th element.
  fn new_block(&mut self, block: SignedBlockSlot, growable: bool) -> Result<()> {
    if block.slot <= self.get_latest_signed_block_slot() {
      bail!("Will not save this slashable evidence!");
    }
    if growable || self.signed_blocks.is_empty() {
      self.signed_blocks.push(block);
    } else {
      self.signed_blocks[0] = block;
    }
    Ok(())
  }

  fn get_latest_signed_attestation_epochs(&self) -> (Epoch, Epoch) {
    match self.signed_attestations.last() {
      None => (0, 0),
      Some(a) => (a.source_epoch, a.target_epoch)
    }
  }

  /// If the SlashingProtectionDB is growable, append the new attestation epochs, otherwise
  /// overwrite the 0th element.
  fn new_attestation(&mut self, attest: SignedAttestationEpochs, growable: bool) -> Result<()> {
    let (prev_src, prev_tgt) = self.get_latest_signed_attestation_epochs();
    if attest.source_epoch < prev_src {
      bail!("Will not save this slashable evidence!");
    }
    if attest.target_epoch <= prev_tgt {
      bail!("Will not save this slashable evidence!");
    }

    if growable || self.signed_attestations.is_empty() {
      self.signed_attestations.push(attest);
    } else {
      self.signed_attestations[0] = attest;
    }
    Ok(())
  }
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedBlockSlot {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_signing_root")]
    pub signing_root: Option<Root>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Specs: https://eips.ethlibrary.io/eip-3076.html
pub struct SlashingProtectionDB {
    pub metadata: SlashingProtectionMetaData,
    pub title: Option<String>,
    pub description: Option<String>,
    pub data: Vec<SlashingProtectionData>
}

impl SlashingProtectionDB {
  pub fn new() -> Self {
    let metadata = SlashingProtectionMetaData {
      interchange_format_version: "5".into(),
      genesis_validators_root: Root::default(),
    };

    SlashingProtectionDB { metadata: metadata, title: None, description: None, data: vec![] }
  }

  pub fn from_str(json: &str) -> Result<Self> {
    let db: SlashingProtectionDB = serde_json::from_str(json)?;
    Ok(db)
  }

  pub fn save(&self) -> Result<()> {


    Ok(())
  }
}


#[cfg(test)]
mod test_serde {
    use super::*;
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

        let db = SlashingProtectionDB::from_str(raw)?;
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

    #[test]
    fn test_new_db() -> Result<()> {
      let db = SlashingProtectionDB::new();
      assert_eq!(db.metadata.interchange_format_version, "5");
      assert_eq!(hex::encode(db.metadata.genesis_validators_root), "0000000000000000000000000000000000000000000000000000000000000000".to_string());
      assert!(db.title.is_none());
      assert!(db.description.is_none());
      assert_eq!(db.data.len(), 0);
      Ok(())
    }

    #[test]
    fn test_blocks() -> Result<()> {
      let pk = BLSPubkey::default();
      let mut data = SlashingProtectionData::new(pk);
      assert_eq!(data.signed_blocks.len(), 0);
      assert_eq!(data.signed_attestations.len(), 0);
      assert_eq!(data.get_latest_signed_block_slot(), 0);

      let b = SignedBlockSlot { slot: 10, signing_root: None};
      let grow = false;
      data.new_block(b, grow)?;

      assert_eq!(data.signed_blocks.len(), 1);
      assert_eq!(data.signed_blocks[0].slot, 10);
      assert_eq!(data.get_latest_signed_block_slot(), 10);

      // growable=false should overwrite 0th index
      let b = SignedBlockSlot { slot: 11, signing_root: None};
      data.new_block(b, grow)?;
      assert_eq!(data.signed_blocks.len(), 1); // same length
      assert_eq!(data.signed_blocks[0].slot, 11);
      assert_eq!(data.get_latest_signed_block_slot(), 11);

      // attempt to save a BAD block (same slot)
      let b = SignedBlockSlot { slot: 11, signing_root: None};
      assert!(data.new_block(b, grow).is_err());
      assert_eq!(data.signed_blocks.len(), 1);
      assert_eq!(data.get_latest_signed_block_slot(), 11);

      // attempt to save a BAD block (decreasing slot)
      let b = SignedBlockSlot { slot: 5, signing_root: None};
      assert!(data.new_block(b, grow).is_err());
      assert_eq!(data.signed_blocks.len(), 1);
      assert_eq!(data.get_latest_signed_block_slot(), 11);

      // allow growth
      let grow = true;
      let b = SignedBlockSlot { slot: 12, signing_root: None};
      data.new_block(b, grow)?;
      assert_eq!(data.signed_blocks.len(), 2);
      assert_eq!(data.signed_blocks[1].slot, 12);
      assert_eq!(data.get_latest_signed_block_slot(), 12);

      // attempt to save a BAD block (same slot)
      let b = SignedBlockSlot { slot: 12, signing_root: None};
      assert!(data.new_block(b, grow).is_err());
      assert_eq!(data.signed_blocks.len(), 2);
      assert_eq!(data.get_latest_signed_block_slot(), 12);

      // attempt to save a BAD block (decreasing slot)
      let b = SignedBlockSlot { slot: 5, signing_root: None};
      assert!(data.new_block(b, grow).is_err());
      assert_eq!(data.signed_blocks.len(), 2);
      assert_eq!(data.get_latest_signed_block_slot(), 12);

      let b = SignedBlockSlot { slot: 5000, signing_root: None};
      data.new_block(b, grow)?;
      assert_eq!(data.signed_blocks.len(), 3);
      assert_eq!(data.get_latest_signed_block_slot(), 5000);
      
      Ok(())

    }

    #[test]
    fn test_attestations() -> Result<()> {
      let pk = BLSPubkey::default();
      let mut data = SlashingProtectionData::new(pk);
      assert_eq!(data.signed_blocks.len(), 0);
      assert_eq!(data.signed_attestations.len(), 0);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (0, 0));

      let a = SignedAttestationEpochs { 
        source_epoch: 0,
        target_epoch: 0,
        signing_root: None,
      };
      // default is 0,0 so this inputs a non-increasing target_epoch (slashable)
      assert!(data.new_attestation(a, false).is_err());

      let grow = false;

      let a = SignedAttestationEpochs { 
        source_epoch: 10,
        target_epoch: 20,
        signing_root: None,
      };
      
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 1);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (10, 20));

      // growable=false should overwrite 0th index
      let a = SignedAttestationEpochs { 
        source_epoch: 20,
        target_epoch: 30,
        signing_root: None,
      };
      
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 1);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 30));

      // attempt to save SLASHABLE decreasing src epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 10, // strictly decrease
        target_epoch: 31, // strictly increase
        signing_root: None,
      };

      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 1);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 30));

      // attempt to save SLASHABLE non-increasing target epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 20, // same => ok
        target_epoch: 30, // same => slashable
        signing_root: None,
      };
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 1);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 30));

      // attempt to save SLASHABLE non-increasing target epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 20, // same => ok
        target_epoch: 29, // decreasing => slashable
        signing_root: None,
      };
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 1);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 30));

      // allow growth
      let grow = true;
      let a = SignedAttestationEpochs { 
        source_epoch: 20, // same => ok
        target_epoch: 31, // increasing => ok
        signing_root: None,
      };
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 2);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 31));

      // attempt to save SLASHABLE decreasing src epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 10, // strictly decrease
        target_epoch: 32, // strictly increase
        signing_root: None,
      };

      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 2);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 31));

      // attempt to save SLASHABLE non-increasing target epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 20, // same => ok
        target_epoch: 31, // same => slashable
        signing_root: None,
      };
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 2);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 31));

      // attempt to save SLASHABLE non-increasing target epoch attestation
      let a = SignedAttestationEpochs { 
        source_epoch: 20, // same => ok
        target_epoch: 29, // decreasing => slashable
        signing_root: None,
      };
      data.new_attestation(a, grow);
      assert_eq!(data.signed_attestations.len(), 2);
      assert_eq!(data.get_latest_signed_attestation_epochs(), (20, 31));
      
      Ok(())

    }


}