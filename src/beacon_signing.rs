use crate::keys;
use crate::beacon_types::*;

use serde::de::value::Error;
use serde::{Deserialize, Serialize};
use serde::ser::{Serializer, SerializeStruct};
use serde::de::Deserializer;
use serde_hex::{SerHex, StrictPfx, CompactPfx};
use anyhow::{Result, Context, bail};

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, typenum, BitList, Bitfield, BitVector};
use tree_hash::merkle_root;

use std::path::PathBuf;
use std::fs;


fn hash_tree_root<T: Encode>(ssz_object: T) -> Root {
    let bytes = ssz_object.as_ssz_bytes();
    let minimum_leaf_count:usize = 0;
    // `minimum_leaf_count` will only be used if it is greater than or equal to the minimum number of leaves that can be created from `bytes`.
    let root = merkle_root(&bytes, minimum_leaf_count);
    println!("Got hash_tree_root {:?}", root);
    // println!("Got root {:?}", root.as_fixed_bytes());
    *root.as_fixed_bytes()
}

/// Return the signing root for the corresponding signing data.
fn compute_signing_root<T: Encode>(ssz_object: T, domain: Domain) -> Root {
    let object_root = hash_tree_root(ssz_object);
    let sign_data = SigningData { 
        object_root, 
        domain 
    };
    hash_tree_root(sign_data)
}

fn write_block_slot(pk_hex: &String, slot: Slot) -> Result<()> {
    let file_path: PathBuf = ["./etc/slashing/blocks/", pk_hex.as_str()].iter().collect();
    if let Some(p) = file_path.parent() { 
        fs::create_dir_all(p).with_context(|| "Failed to create slashing dir")?
    }; 
    fs::write(&file_path, slot.to_le_bytes()).with_context(|| "failed to write slot") 
}

/// If there is no block saved with fname `pk_hex` then return the default slot of 0 
fn read_block_slot(pk_hex: &String) -> Result<Slot> {
    match fs::read(&format!("./etc/slashing/blocks/{}", pk_hex)) {
        Ok(slot) => {
            // Convert slot form little endian bytes
            let mut s: [u8; 8] = [0_u8; 8];
            s.iter_mut().zip(slot[0..8].iter()).for_each(|(to, from)| *to = *from);
            Ok(u64::from_le_bytes(s))
        },
        // No existing slot. return default 0
        Err(e) => Ok(0)
    }
}

// fn write_block(pk_hex: &String, b: &BeaconBlock) -> Result<()> {
//     let file_path: PathBuf = ["./etc/slashing/blocks/", pk_hex.as_str()].iter().collect();
//     if let Some(p) = file_path.parent() { 
//         fs::create_dir_all(p).with_context(|| "Failed to create slashing/blocks dir")?
//     }; 
//     let bs = b.as_ssz_bytes();
//     println!("bs: {:?}", bs);
//     fs::write(&file_path, bs).with_context(|| "failed to write block") 
// }

// note currently this is not decoding correctly
// /// If there is no block saved with fname `pk_hex` then return the default slot of 0 
// fn read_block(pk_hex: &String) -> Result<BeaconBlock> {
//     match fs::read(&format!("./etc/slashing/blocks/{}", pk_hex)) {
//         Ok(b) => {
//             println!("b: {:?}", b);
//             match BeaconBlock::from_ssz_bytes(&b) {
//                 Ok(bb) => Ok(bb),
//                 Err(e) => bail!("Error, could not ssz decode previous block {:?}", e)
//             }
//         },
//         // No existing slot. return default 0
//         Err(e) => Ok(BeaconBlock::default())
//     }
// }

fn write_attestation_data(pk_hex: &String, d: &AttestationData) -> Result<()>{
    let file_path: PathBuf = ["./etc/slashing/attestations/", pk_hex.as_str()].iter().collect();
    if let Some(p) = file_path.parent() { 
        fs::create_dir_all(p).with_context(|| "Failed to create attestations dir")?
    }; 
    let s = d.source.epoch.to_le_bytes();
    let t = d.target.epoch.to_le_bytes();
    let data = [&s[..], &t[..]].concat();
    fs::write(&file_path, data).with_context(|| "failed to write attestation epochs") 
}

fn read_attestation_data(pk_hex: &String) -> Result<(Epoch, Epoch)> {
    match fs::read(&format!("./etc/slashing/blocks/{}", pk_hex)) {
        Ok(data) => {
            // Convert slot form little endian bytes
            let mut source: [u8; 8] = [0_u8; 8];
            let mut target: [u8; 8] = [0_u8; 8];
            source.iter_mut().zip(data[0..8].iter()).for_each(|(to, from)| *to = *from);
            target.iter_mut().zip(data[8..16].iter()).for_each(|(to, from)| *to = *from);
            Ok((u64::from_le_bytes(source), u64::from_le_bytes(target)))
        },
        // No existing attsetation data. return default (0,0)
        Err(e) => Ok((0, 0))
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProposeBlockRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestBlockRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub attestation: AttestationData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RandaoRevealRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub randao_reveal: Epoch,
}

/// Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
/// This is used primarily in signature domains to avoid collisions across forks/chains.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    let f = ForkData {
        current_version,
        genesis_validators_root,
    };
    hash_tree_root(f)
}

/// Return the domain for the ``domain_type`` and ``fork_version``.
pub fn compute_domain(domain_type: DomainType, fork_version: Option<Version>, genesis_validators_root: Option<Root>) -> Domain {
    let fv = match fork_version {
        Some(fv) => fv, 
        None => GENESIS_FORK_VERSION
    };

    let gvr = match genesis_validators_root {
        Some(gvr) => gvr, 
        None => [0_u8; 32] // all bytes zero by default
    };
    let fork_data_root = compute_fork_data_root(fv, gvr);
    let mut d = [0_u8; 32]; // domain_type + fork_data_root[:28]
    domain_type.iter().enumerate().for_each(|(i, v)| d[i] = *v);
    d[4..32].iter_mut().zip(fork_data_root[0..28].iter()).for_each(|(src, dest)| *src = *dest);
    d
}

pub fn secure_sign_block(pk_hex: String, block: BeaconBlock, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, block: {:?}, domain: {:?}", pk_hex, block, domain);
    // read previous slot from mem
	let previous_block_slot = read_block_slot(&pk_hex)?;   

	// The block slot number must be strictly increasing to prevent slashing
	assert!(block.slot > previous_block_slot);
 
    // write current slot to mem
	write_block_slot(&pk_hex, block.slot)?;

    let root: Root = compute_signing_root(block, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_attestation(pk_hex: String, attestation_data: AttestationData, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, attestation_data: {:?}, domain: {:?}", pk_hex, attestation_data, domain);
	let (prev_src_epoch, prev_tgt_epoch) = read_attestation_data(&pk_hex)?;

	// The attestation source epoch must be non-decreasing to prevent slashing
	assert!(attestation_data.source.epoch >= prev_src_epoch);

	// The attestation target epoch must be strictly increasing to prevent slashing
	assert!(attestation_data.target.epoch > prev_tgt_epoch);

    write_attestation_data(&pk_hex, &attestation_data)?;

    let root: Root = compute_signing_root(attestation_data, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_randao(pk_hex: String, epoch: Epoch, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, epoch: {:?}, domain: {:?}", pk_hex, epoch, domain);
    let root: Root = compute_signing_root(epoch, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

#[cfg(test)]
mod spec_tests {
    use super::*;
    // use crate::beacon_types::*;

    // #[test]
    // fn test_serialize() {
    //     let bb = BeaconBlock::default(); 

    //     println!("{:?}", bb);
    //     let bytes = bb.as_ssz_bytes();
    //     println!("{:?}", bytes);
    //     println!("{:?}", BeaconBlock::from_ssz_bytes(&bytes).unwrap());
    // }

    // #[test]
    // fn test_secure_sign_randao() -> Result<()> {
    //     let pk_hex = String::from("8b17b1964fdfa87e8f172b09123f0e12cbc8195ee709bfb16545c7da2d98c9ab628ea74e786be0c08566efd366795a6a");
    //     let epoch = 123;
    //     let domain = Domain {  };
    //     secure_sign_randao(pk_hex, epoch, domain)?;
    //     Ok(())
    // }

    #[test]
    fn test_deserialize_fork() -> Result<()> {
        let req = r#"
            {
                "previous_version":"0x00000001",
                "current_version":"0x00000001",
                "epoch":"10"
            }"#;

        let v: Fork = serde_json::from_str(req)?;
        assert_eq!(v.previous_version, [0, 0, 0, 1]);
        assert_eq!(v.current_version, [0, 0, 0, 1]);
        assert_eq!(v.epoch, 16); // 10 == 0x10 == 16
        Ok(())
    }

    #[test]
    fn test_deserialize_fork_info() -> Result<()> {
        let req = r#"
            {
                "fork":{
                    "previous_version":"0x00000001",
                    "current_version":"0x00000001",
                    "epoch":"0xff"
                },
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            }"#;

        let v: ForkInfo = serde_json::from_str(req)?;
        assert_eq!(v.fork.previous_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.current_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.epoch, 255); 
        // python: list(bytes.fromhex('04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673'))
        assert_eq!(v.genesis_validators_root, [4, 112, 0, 7, 250, 188, 130, 130, 100, 74, 237, 109, 28, 124, 158, 33, 211, 138, 3, 160, 196, 186, 25, 63, 58, 254, 66, 136, 36, 179, 166, 115]);
        assert_eq!(hex::encode(v.genesis_validators_root), "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673");
        Ok(())
    }
    
    #[test]
    fn test_deserialize_deposit_data() -> Result<()> {
        let pk = keys::bls_key_gen(true)?;
        let bls_pk_hex = hex::encode(pk.compress());
        let sig = keys::bls_sign(&bls_pk_hex, b"hello world")?;
        keys::verify_bls_sig(sig, pk, b"hello world").unwrap();
        let hex_sig = hex::encode(sig.compress());
        println!("pk: {bls_pk_hex}");
        println!("sig: {hex_sig}");
        let withdrawal = "0x0000000000000000000000000000000000000000000000000000000000000001";
        // test deserialize bls pk and bls sig
        let req = format!(r#"
            {{
                "pubkey": "{bls_pk_hex}",
                "withdrawal_credentials":"{withdrawal}",
                "amount":"0xdeadbeef",
                "signature": "{hex_sig}"
            }}"#);

        let dd: DepositData = serde_json::from_str(&req)?;
        let mut exp_w = [0_u8; 32];
        exp_w[31] = 1;
        assert_eq!(dd.withdrawal_credentials, exp_w);
        assert_eq!(dd.amount, 3735928559);

        let got_pk = dd.pubkey;
        let got_pk_hex = hex::encode(&got_pk[..]);
        let got_pk = keys::bls_pk_from_hex(got_pk_hex)?;
        
        let got_sig = dd.signature;
        let got_sig_hex = hex::encode(&got_sig[..]);
        let got_sig = keys::bls_sig_from_hex(got_sig_hex)?;
        keys::verify_bls_sig(got_sig, got_pk, b"hello world")
    }
}


#[cfg(test)]
mod secure_signer_tests {
    use super::*;
    use std::fs;

    /// hardcoded bls sk
    fn setup_keypair() -> String {
        let sk_hex: String = "3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35".into();
        let sk = keys::bls_sk_from_hex(sk_hex.clone()).unwrap();
        let pk = sk.sk_to_pk();
        let pk_hex = hex::encode(pk.compress());
        assert_eq!(pk_hex, "989d34725a2bfc3f15105f3f5fc8741f436c25ee1ee4f948e425d6bcb8c56bce6e06c269635b7e985a7ffa639e2409bf");
        keys::write_key(&format!("bls_keys/generated/{}", pk_hex), &sk_hex).with_context(|| "failed to save bls key").unwrap();
        pk_hex
    }

    fn mock_propose_block_request(slot: &str) -> String {
        let type_: String = "BlOcK".into(); // mixed case

        let req = format!(r#"
            {{
               "type":"{type_}",
               "fork_info":{{
                  "fork":{{
                     "previous_version":"0x00000001",
                     "current_version":"0x00000001",
                     "epoch":"0"
                  }},
                  "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
               }},
               "block":{{
                  "slot":"{slot}",
                  "proposer_index":"5",
                  "parent_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
                  "state_root":"0x2b530d6262576277f1cc0dbe341fd919f9f8c5c92fc9140dff6db4ef34edea0d",
                  "body":{{
                     "randao_reveal":"0xa686652aed2617da83adebb8a0eceea24bb0d2ccec9cd691a902087f90db16aa5c7b03172a35e874e07e3b60c5b2435c0586b72b08dfe5aee0ed6e5a2922b956aa88ad0235b36dfaa4d2255dfeb7bed60578d982061a72c7549becab19b3c12f",
                     "eth1_data":{{
                        "deposit_root":"0x6a0f9d6cb0868daa22c365563bb113b05f7568ef9ee65fdfeb49a319eaf708cf",
                        "deposit_count":"8",
                        "block_hash":"0x4242424242424242424242424242424242424242424242424242424242424242"
                     }},
                     "graffiti":"0x74656b752f76302e31322e31302d6465762d6338316361363235000000000000",
                     "proposer_slashings":[],
                     "attester_slashings":[],
                     "attestations":[],
                     "deposits":[],
                     "voluntary_exits":[]
                  }}
               }},
               "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }}"#);
        // println!("{req}");
        req
    }

    #[test]
    fn test_propose_block_request() -> Result<()>{
        // clear state
        fs::remove_dir_all("./etc")?;

        // new key
        let bls_pk_hex = setup_keypair();

        let n = 10;
        for s in 1..n {
            let slot = format!("{s:x}");
            let req = mock_propose_block_request(&slot);
            let pbr: ProposeBlockRequest = serde_json::from_str(&req)?;
            assert_eq!(pbr.block.slot, s);

            let domain = compute_domain(
                DOMAIN_BEACON_PROPOSER, 
                Some(pbr.fork_info.fork.current_version),
                Some(pbr.fork_info.genesis_validators_root)
            );
            let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain)?;
            println!("sig: {}", hex::encode(sig.to_vec()));
        }
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_propose_block_prevents_slash() {
        // clear state
        fs::remove_dir_all("./etc").unwrap();

        // new key
        let bls_pk_hex = setup_keypair();

        let s = 100;
        let slot = format!("{s:x}");
        let req = mock_propose_block_request(&slot);
        let pbr: ProposeBlockRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(pbr.block.slot, s);

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER, 
            Some(pbr.fork_info.fork.current_version),
            Some(pbr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain).unwrap();
        println!("sig: {}", hex::encode(sig.to_vec()));

        // make one more request using an old slot and expect panic
        let s = 50;
        let slot = format!("{s:x}");
        let req = mock_propose_block_request(&slot);
        let pbr: ProposeBlockRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(pbr.block.slot, s);

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER, 
            Some(pbr.fork_info.fork.current_version),
            Some(pbr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain).unwrap();
    }

}