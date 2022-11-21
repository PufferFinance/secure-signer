use crate::keys;

use serde::de::value::Error;
use serde::{Deserialize, Serialize};
use serde::ser::{Serializer, SerializeStruct};
use serde::de::Deserializer;
use serde_hex::{SerHex, StrictPfx, CompactPfx};
use anyhow::{Result, Context, bail};

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, typenum, BitList, Bitfield};
use tree_hash::merkle_root;

/// Types
pub type Bytes4  = [u8; 4];
pub type Bytes32 = [u8; 32];
pub type Bytes48 = FixedVector<u8, typenum::U48>;
pub type Bytes96 = FixedVector<u8, typenum::U96>;
pub type Hash32 = Bytes32;
pub type Slot = u64;
pub type Epoch = u64;
pub type CommitteeIndex = u64;
pub type ValidatorIndex = u64;
pub type Root = Bytes32; 
pub type BLSSignature = Bytes96;
pub type BLSPubkey = Bytes48;
pub type Version = Bytes4;
pub type Gwei = u64;
pub type DomainType = Bytes4;

// typenums for specifying the length of FixedVector
type MAX_VALIDATORS_PER_COMMITTEE = typenum::U2048;
type DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE = typenum::U33;
type MAX_PROPOSER_SLASHINGS = typenum::U16;
type MAX_ATTESTER_SLASHINGS = typenum::U2;
type MAX_ATTESTATIONS = typenum::U128;
type MAX_DEPOSITS = typenum::U16;
type MAX_VOLUNTARY_EXITS = typenum::U16;

pub const DOMAIN_BEACON_PROPOSER:     DomainType = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'
pub const DOMAIN_BEACON_ATTESTER:     DomainType = [1_u8, 0_u8, 0_u8, 0_u8]; // '0x01000000'
pub const DOMAIN_RANDAO:              DomainType = [2_u8, 0_u8, 0_u8, 0_u8]; // '0x02000000'
pub const DOMAIN_DEPOSIT:             DomainType = [3_u8, 0_u8, 0_u8, 0_u8]; // '0x03000000'
pub const DOMAIN_VOLUNTARY_EXIT:      DomainType = [4_u8, 0_u8, 0_u8, 0_u8]; // '0x04000000'
pub const DOMAIN_SELECTION_PROOF:     DomainType = [5_u8, 0_u8, 0_u8, 0_u8]; // '0x05000000'
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [6_u8, 0_u8, 0_u8, 0_u8]; // '0x06000000'
pub const DOMAIN_APPLICATION_MASK:    DomainType = [0_u8, 0_u8, 0_u8, 1_u8]; // '0x00000001'

pub const GENESIS_FORK_VERSION: Version = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'

pub fn from_bls_pk_hex<'de, D>(deserializer: D) -> Result<BLSPubkey, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_bls_pk_hex");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    println!("hex_str: {:?}", hex_str);
    let bytes = hex::decode(hex_str).expect("failed to deserialize");
    println!("bytes: {:?}", bytes);
    // let bytes = hex::decode(hex_str).map_err(D::Error::custom);
    // let bytes = match hex::decode(hex_str) {
    //     Ok(bs) => bs,
    //     Err(e) => return Err()
    // };
    let pk: BLSPubkey = FixedVector::from(bytes);
    Ok(pk)
}
pub fn from_bls_sig_hex<'de, D>(deserializer: D) -> Result<BLSSignature, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_bls_sig_hex");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(hex_str).expect("failed to deserialize");
    let pk: BLSSignature = FixedVector::from(bytes);
    Ok(pk)
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Fork {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub previous_version: Version,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub current_version: Version,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub epoch: Epoch,
}

#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct ForkData {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub current_version: Version,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Root,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ForkInfo {
    pub fork: Fork,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Checkpoint {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub epoch: Epoch,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct RandaoReveal {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub epoch: Epoch
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct AttestationData {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub index: CommitteeIndex,
//     # LMD GHOST vote
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
//    # FFG vote
    pub source: Checkpoint,
    pub target: Checkpoint
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct BeaconBlockHeader {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub proposer_index: ValidatorIndex,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub body_root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct IndexedAttestation {
    pub attesting_indices: FixedVector<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Eth1Data {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub deposit_root: Root,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub deposit_count: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub block_hash: Hash32,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct DepositData {
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub amount: Gwei,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,  // Signing over DepositMessage
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Deposit {
    pub proof: FixedVector<Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE>,  // Merkle path to deposit root
    pub data: DepositData,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct VoluntaryExit {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub epoch: Epoch,  // Earliest epoch when voluntary exit can be processed
    #[serde(with = "SerHex::<CompactPfx>")]
    pub validator_index: ValidatorIndex,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone)]
pub struct Attestation {
    pub aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

impl Default for Attestation {
    fn default() -> Self {
        Attestation {
            aggregation_bits: Bitfield::with_capacity(2048).unwrap(),
            data: AttestationData::default(),
            signature: BLSSignature::default(),
        }
    }
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone)]
pub struct BeaconBlockBody {
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub randao_reveal: BLSSignature,
    pub eth1_data: Eth1Data,  // Eth1 data vote
    #[serde(with = "SerHex::<StrictPfx>")]
    pub graffiti: Bytes32,  // Arbitrary data
    // Operations,
    pub proposer_slashings: FixedVector<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    pub attester_slashings: FixedVector<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    pub attestations: FixedVector<Attestation, MAX_ATTESTATIONS>,
    pub deposits: FixedVector<Deposit, MAX_DEPOSITS>,
    pub voluntary_exits: FixedVector<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

impl Default for BeaconBlockBody {
    fn default() -> Self {
        BeaconBlockBody { 
            randao_reveal: BLSSignature::default(),
            eth1_data: Eth1Data::default(), 
            graffiti: Bytes32::default(), 
            proposer_slashings: <_>::from(vec![ProposerSlashing::default(); 16]),
            attester_slashings: <_>::from(vec![AttesterSlashing::default(); 2]),
            attestations: <_>::from(vec![Attestation::default(); 128]), 
            deposits: <_>::from(vec![Deposit::default(); 16]), 
            voluntary_exits: <_>::from(vec![SignedVoluntaryExit::default(); 16]), 
        }
    }
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct BeaconBlock {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub proposer_index: ValidatorIndex,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SigningData {
    #[serde(with = "SerHex::<StrictPfx>")]
    object_root: Root,
    domain: Domain,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Domain {
    // TODO
}

fn hash_tree_root<T: Encode>(ssz_object: T) -> Root {
    let bytes = ssz_object.as_ssz_bytes();
    let minimum_leaf_count:usize = 0;
    // `minimum_leaf_count` will only be used if it is greater than or equal to the minimum number of leaves that can be created from `bytes`.
    let root = merkle_root(&bytes, minimum_leaf_count);
    println!("Got root {:?}", root);
    println!("Got root {:?}", root.as_fixed_bytes());
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

fn write_block(b: BeaconBlock) {
    unimplemented!()
}

fn read_block() -> BeaconBlock {
    unimplemented!()
}

fn write_attestation_data(d: AttestationData) {
    unimplemented!()
}

fn read_attestation_data() -> AttestationData {
    unimplemented!()
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProposeBlockRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    pub signingRoot: Root,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestBlockRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    pub signingRoot: Root,
    pub attestation: AttestationData,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RandaoRevealRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub fork_info: ForkInfo,
    pub signingRoot: Root,
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
    let mut d: Vec<u8> = Vec::new(); // domain_type + fork_data_root[:28]
    d.extend(domain_type.as_slice().to_vec());
    d.extend(fork_data_root[..28].to_vec());
    d;
    unimplemented!()
}

pub fn secure_sign_block(pk_hex: String, block: BeaconBlock, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, block: {:?}, domain: {:?}", pk_hex, block, domain);
	// let previous_block = read_block();
	// // The block slot number must be strictly increasing to prevent slashing
	// assert!(block.slot > previous_block.slot);
	// write_block(block.clone());

    // let sk = keys::read_key(&pk_hex).expect("Couldn't fetch pk");

    // let root: Root = compute_signing_root(block, domain);

    // let sig = sk.sign(&root, keys::CIPHER_SUITE, &[]);

    // <_>::from(sig.to_bytes().to_vec())
    bail!("unimplemented")
}

pub fn secure_sign_attestation(pk_hex: String, attestation_data: AttestationData, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, attesetation_data: {:?}, domain: {:?}", pk_hex, attestation_data, domain);
	// let previous_attestation_data = read_attestation_data();

	// // The attestation source epoch must be non-decreasing to prevent slashing
	// assert!(attestation_data.source.epoch >= previous_attestation_data.source.epoch);

	// // The attestation target epoch must be strictly increasing to prevent slashing
	// assert!(attestation_data.target.epoch > previous_attestation_data.target.epoch);

    // write_attestation_data(attestation_data.clone());

    // let sk = keys::read_key(&pk_hex).expect("Couldn't fetch pk");

    // let root: Root = compute_signing_root(attestation_data, domain);

    // let sig = sk.sign(&root, keys::CIPHER_SUITE, &[]);

    // <_>::from(sig.to_bytes().to_vec())
    bail!("unimplemented")
}

pub fn secure_sign_randao(pk_hex: String, epoch: Epoch, domain: Domain) -> Result<BLSSignature> {
    println!("pk_hex: {:?}, epoch: {:?}, domain: {:?}", pk_hex, epoch, domain);
    // let sk = keys::read_key(&pk_hex).expect("Couldn't fetch pk");

    // let root: Root = compute_signing_root(epoch, domain);

    // let sig = sk.sign(&root, keys::CIPHER_SUITE, &[]);

    // <_>::from(sig.to_bytes().to_vec())
    bail!("unimplemented")
}

#[cfg(test)]
mod spec_tests {
    use super::*;

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
                "genesis_validators_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }"#;

        let v: ForkInfo = serde_json::from_str(req)?;
        assert_eq!(v.fork.previous_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.current_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.epoch, 255); 
        // python: list(bytes.fromhex('270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69'))
        assert_eq!(v.genesis_validators_root, [39, 13, 67, 231, 76, 227, 64, 222, 75, 202, 43, 25, 54, 190, 202, 15, 79, 84, 8, 217, 231, 138, 236, 72, 80, 146, 11, 175, 101, 157, 91, 105]);
        assert_eq!(hex::encode(v.genesis_validators_root), "270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69");
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


    fn mock_propose_block_request() {
        let type_: String = "BlOcK".into(); // mixed case


        // let fork = Fork {
        //     previous_version: "0x00000001",
        //     current_version: "0x00000001",
        //     epoch: 
        // }
        // let fork_info = ForkInfo { fork: (), genesis_validators_root: () };
        // let signingRoot: Root =  [0_u8; 32];

        // let req = r#"
        //        "type":"block",
        //        "fork_info":{
        //           "fork":{
        //              "previous_version":"0x00000001",
        //              "current_version":"0x00000001",
        //              "epoch":"0"
        //           },
        //           "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
        //        },
        //        "block":{
        //           "slot":"${slot}",
        //           "proposer_index":"5",
        //           "parent_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
        //           "state_root":"0x2b530d6262576277f1cc0dbe341fd919f9f8c5c92fc9140dff6db4ef34edea0d",
        //           "body":{
        //              "randao_reveal":"0xa686652aed2617da83adebb8a0eceea24bb0d2ccec9cd691a902087f90db16aa5c7b03172a35e874e07e3b60c5b2435c0586b72b08dfe5aee0ed6e5a2922b956aa88ad0235b36dfaa4d2255dfeb7bed60578d982061a72c7549becab19b3c12f",
        //              "eth1_data":{
        //                 "deposit_root":"0x6a0f9d6cb0868daa22c365563bb113b05f7568ef9ee65fdfeb49a319eaf708cf",
        //                 "deposit_count":"8",
        //                 "block_hash":"0x4242424242424242424242424242424242424242424242424242424242424242"
        //              },
        //              "graffiti":"0x74656b752f76302e31322e31302d6465762d6338316361363235000000000000",
        //              "proposer_slashings":[],
        //              "attester_slashings":[],
        //              "attestations":[],
        //              "deposits":[],
        //              "voluntary_exits":[]
        //           }
        //        }
        //     }
        //     "

        // let req = ProposeBlockRequest {
        //     type_,
        //     fork_info,
        //     signingRoot,
        //     block
        // }

    }
}