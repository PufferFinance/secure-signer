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

fn write_attestation_data(pk_hex: &String, d: &AttestationData) -> Result<()>{
    let file_path: PathBuf = ["./etc/slashing/attestations/", pk_hex.as_str()].iter().collect();
    if let Some(p) = file_path.parent() { 
        fs::create_dir_all(p).with_context(|| "Failed to create attestations dir")?
    }; 
    let s = d.source.epoch.to_le_bytes();
    let t = d.target.epoch.to_le_bytes();
    let data = [&s[..], &t[..]].concat();
    // println!("Writing attestation data: {:?}", data);
    fs::write(&file_path, data).with_context(|| "failed to write attestation epochs") 
}

fn read_attestation_data(pk_hex: &String) -> Result<(Epoch, Epoch)> {
    match fs::read(&format!("./etc/slashing/attestations/{}", pk_hex)) {
        Ok(data) => {
            // println!("Reading attestation data: {:?}", data);
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
pub struct BlockRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub attestation: AttestationData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RandaoRevealRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub randao_reveal: Epoch,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AggregateAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub aggregate_and_proof: AggregateAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AggregationSlotRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub aggregation_slot: AggregationSlot,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DepositRequest {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub deposit: DepositData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VoluntaryExitRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub voluntary_exit: VoluntaryExit,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeMessageRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub sync_committee_message: SyncCommitteeMessage,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeSelectionProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub sync_aggregator_selection_data: SyncAggregatorSelectionData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SyncCommitteeContributionAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub contribution_and_proof: ContributionAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ValidatorRegistrationRequest {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub validator_registration: ValidatorRegistration,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum BLSSignMsg {
    BLOCK (BlockRequest),
    ATTESTATION (AttestationRequest),
    RANDAO_REVEAL (RandaoRevealRequest),
    AGGREGATE_AND_PROOF (AggregateAndProofRequest),
    AGGREGATION_SLOT (AggregationSlotRequest),
    DEPOSIT (DepositRequest),
    VOLUNTARY_EXIT (VoluntaryExitRequest),
    SYNC_COMMITTEE_MESSAGE (SyncCommitteeMessageRequest),
    SYNC_COMMITTEE_SELECTION_PROOF (SyncCommitteeSelectionProofRequest),
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF (SyncCommitteeContributionAndProofRequest),
    // VALIDATOR_REGISTRATION (ValidatorRegistrationRequest), //todo
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
	if block.slot <= previous_block_slot {
        bail!("block.slot <= previous_block_slot")
    }
 
    // write current slot to mem
	write_block_slot(&pk_hex, block.slot)?;

    let root: Root = compute_signing_root(block, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_attestation(pk_hex: String, attestation_data: AttestationData, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, attestation_data: {:?}, domain: {:?}", pk_hex, attestation_data, domain);
	let (prev_src_epoch, prev_tgt_epoch) = read_attestation_data(&pk_hex)?;
    println!("src_epoch: {}, prev: {} ... tgt_epoch: {}, prev: {}", attestation_data.source.epoch, prev_src_epoch, attestation_data.target.epoch, prev_tgt_epoch);

	// The attestation source epoch must be non-decreasing to prevent slashing
	if attestation_data.source.epoch < prev_src_epoch {
        bail!("attestation_data.source.epoch < prev_src_epoch")
    }

	// The attestation target epoch must be strictly increasing to prevent slashing
	if attestation_data.target.epoch <= prev_tgt_epoch {
        bail!("attestation_data.target.epoch <= prev_tgt_epoch")
    }

    write_attestation_data(&pk_hex, &attestation_data)?;

    let root: Root = compute_signing_root(attestation_data, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_randao_reveal(pk_hex: String, epoch: Epoch, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, epoch: {:?}, domain: {:?}", pk_hex, epoch, domain);
    let root: Root = compute_signing_root(epoch, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_aggregate_and_proof(pk_hex: String, aap: AggregateAndProof, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, aap: {:?}, domain: {:?}", pk_hex, aap, domain);
    let root: Root = compute_signing_root(aap, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_aggregation_slot(pk_hex: String, ags: AggregationSlot, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, ags: {:?}, domain: {:?}", pk_hex, ags, domain);
    let root: Root = compute_signing_root(ags, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_deposit(pk_hex: String, d: DepositData, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, d: {:?}, domain: {:?}", pk_hex, d, domain);
    let root: Root = compute_signing_root(d, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_voluntary_exit(pk_hex: String, ve: VoluntaryExit, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, ve: {:?}, domain: {:?}", pk_hex, ve, domain);
    let root: Root = compute_signing_root(ve, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_sync_committee_msg(pk_hex: String, scm: SyncCommitteeMessage, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, scm: {:?}, domain: {:?}", pk_hex, scm, domain);
    let root: Root = compute_signing_root(scm, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_sync_committee_selection_proof(pk_hex: String, sasd: SyncAggregatorSelectionData, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, sasd: {:?}, domain: {:?}", pk_hex, sasd, domain);
    let root: Root = compute_signing_root(sasd, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_sync_committee_contribution_and_proof(pk_hex: String, cap: ContributionAndProof, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, cap: {:?}, domain: {:?}", pk_hex, cap, domain);
    let root: Root = compute_signing_root(cap, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

pub fn secure_sign_validator_registration(pk_hex: String, vr: ValidatorRegistration, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, vr: {:?}, domain: {:?}", pk_hex, vr, domain);
    let root: Root = compute_signing_root(vr, domain);
    let sig = keys::bls_sign(&pk_hex, &root)?;
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

#[cfg(test)]
mod spec_tests {

}

#[cfg(test)]
pub mod slash_resistance_tests {
    use super::*;
    use std::fs;

    /// hardcoded bls sk
    pub fn setup_keypair() -> String {
        let sk_hex: String = "3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35".into();
        let sk = keys::bls_sk_from_hex(sk_hex.clone()).unwrap();
        let pk = sk.sk_to_pk();
        let pk_hex = hex::encode(pk.compress());
        assert_eq!(pk_hex, "989d34725a2bfc3f15105f3f5fc8741f436c25ee1ee4f948e425d6bcb8c56bce6e06c269635b7e985a7ffa639e2409bf");
        keys::write_key(&format!("bls_keys/generated/{}", pk_hex), &sk_hex).with_context(|| "failed to save bls key").unwrap();
        pk_hex
    }

    #[test]
    fn test_enum() {
        let req = mock_propose_block_request("0x5");
        let x: BLSSignMsg = serde_json::from_str(&req).unwrap();
        println!("{:?}", x);
        match x {
            BLSSignMsg::BLOCK(x) => {
                println!("{:?}", x.fork_info);
            },
            _ => {}
        }
        // let y: ProposeBlockRequest = x.try_into().unwrap();
        // println!("{:?}", y);
    }

    pub fn mock_propose_block_request(slot: &str) -> String {
        // let type_: String = "BlOcK".into(); // mixed case
        let type_: String = "BLOCK".into(); 

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

    fn send_n_proposals(n: u64) -> (String, Vec<BLSSignature>) {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // make n requests
        let sigs = (1..n+1).map(|s| {
            let slot = format!("{s:x}");
            let req = mock_propose_block_request(&slot);
            let pbr: BlockRequest = serde_json::from_str(&req).unwrap();
            assert_eq!(pbr.block.slot, s);

            let domain = compute_domain(
                DOMAIN_BEACON_PROPOSER, 
                Some(pbr.fork_info.fork.current_version),
                Some(pbr.fork_info.genesis_validators_root)
            );
            let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain).unwrap();
            println!("sig: {}", hex::encode(sig.to_vec()));
            sig
        }).collect();
        (bls_pk_hex, sigs)
    }

    #[test]
    fn test_propose_block_request() -> Result<()>{
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_proposals(n);
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_propose_block_prevents_slash_when_decreasing_slot() {
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_proposals(n);

        // make a request with slot < n and expect panic
        let s = n - 1;
        let slot = format!("{s:x}");
        let req = mock_propose_block_request(&slot);
        let pbr: BlockRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(pbr.block.slot, s);

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER, 
            Some(pbr.fork_info.fork.current_version),
            Some(pbr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_propose_block_prevents_slash_when_non_increasing_slot() {
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_proposals(n);

        // make a request with slot = n and expect panic
        let s = n;
        let slot = format!("{s:x}");
        let req = mock_propose_block_request(&slot);
        let pbr: BlockRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(pbr.block.slot, s);

        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER, 
            Some(pbr.fork_info.fork.current_version),
            Some(pbr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_block(bls_pk_hex.clone(), pbr.block, domain).unwrap();
    }

    pub fn mock_attestation_request(src_epoch: &str, tgt_epoch: &str) -> String {
        // let type_: String = "aTteStatION".into(); // mixed case
        let type_: String = "ATTESTATION".into(); 

        let req = format!(r#"
        {{
            "type": "{type_}",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x00000001",
                   "current_version":"0x00000001",
                   "epoch":"0"
                }},
                "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }},
            "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
            "attestation": {{
                "slot": "0xff",
                "index": "0xffff",
                "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                "source": {{
                    "epoch": "{src_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }},
                "target": {{
                    "epoch": "{tgt_epoch}",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }}
            }}
        }}"#);
        // println!("{req}");
        req
    }

    fn send_n_attestations(n: u64) -> (String, Vec<BLSSignature>) {
        // clear state
        fs::remove_dir_all("./etc");

        // new keypair
        let bls_pk_hex = setup_keypair();

        // make n requests
        let sigs = (1..n+1).map(|s| {
            // source epoch will be non-decreasing
            let src_epoch = format!("{s:x}");
            // target epoch will be strictly increasing
            let tgt_epoch = format!("{s:x}");
            let req = mock_attestation_request(&src_epoch, &tgt_epoch);
            let abr: AttestationRequest = serde_json::from_str(&req).unwrap();
            assert_eq!(abr.attestation.slot, 255);
            assert_eq!(abr.attestation.index, 65535);
            assert_eq!(abr.attestation.source.epoch, s);
            assert_eq!(abr.attestation.target.epoch, s);

            let domain = compute_domain(
                DOMAIN_BEACON_ATTESTER, 
                Some(abr.fork_info.fork.current_version),
                Some(abr.fork_info.genesis_validators_root)
            );
            let sig : BLSSignature = secure_sign_attestation(bls_pk_hex.clone(), abr.attestation, domain).unwrap();
            println!("sig: {}", hex::encode(sig.to_vec()));
            sig
        }).collect();
        (bls_pk_hex, sigs)
    }

    #[test]
    fn test_attestation_request() -> Result<()>{
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_attestations(n);
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_attestation_request_prevents_slash_when_decreasing_src_epoch(){
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_attestations(n);

        // prev src epoch should be 50, but send 0
        let src_epoch = "0x0";

        // target epoch will be strictly increasing
        let tgt_epoch = format!("{:x}", n + 1);

        let req = mock_attestation_request(&src_epoch, &tgt_epoch);
        let abr: AttestationRequest = serde_json::from_str(&req).unwrap();

        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER, 
            Some(abr.fork_info.fork.current_version),
            Some(abr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_attestation(bls_pk_hex.clone(), abr.attestation, domain).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_attestation_request_prevents_slash_when_non_increasing_tgt_epoch(){
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_attestations(n);

        // prev src epoch should be non-decreasing
        let src_epoch = format!("{:x}", n + 1);
        // target epoch will be equal (non-increasing)
        let tgt_epoch = format!("{:x}", n);

        let req = mock_attestation_request(&src_epoch, &tgt_epoch);
        let abr: AttestationRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(abr.attestation.slot, 255);
        assert_eq!(abr.attestation.index, 65535);
        assert_eq!(abr.attestation.source.epoch, n+1);
        assert_eq!(abr.attestation.target.epoch, n);

        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER, 
            Some(abr.fork_info.fork.current_version),
            Some(abr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_attestation(bls_pk_hex.clone(), abr.attestation, domain).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_attestation_request_prevents_slash_when_decreasing_tgt_epoch(){
        let n = 50;
        let (bls_pk_hex, sigs) = send_n_attestations(n);

        // prev src epoch should be non-decreasing
        let src_epoch = format!("{:x}", n + 1);
        // target epoch will be decreasing
        let tgt_epoch = "0x0";

        let req = mock_attestation_request(&src_epoch, &tgt_epoch);
        let abr: AttestationRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(abr.attestation.slot, 255);
        assert_eq!(abr.attestation.index, 65535);
        assert_eq!(abr.attestation.source.epoch, n + 1);
        assert_eq!(abr.attestation.target.epoch, 0);

        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER, 
            Some(abr.fork_info.fork.current_version),
            Some(abr.fork_info.genesis_validators_root)
        );
        let sig : BLSSignature = secure_sign_attestation(bls_pk_hex.clone(), abr.attestation, domain).unwrap();
    }
}