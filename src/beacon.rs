use crate::keys;

use serde::{Deserialize, Serialize};
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

// typenums for specifying the length of FixedVector
type MAX_VALIDATORS_PER_COMMITTEE = typenum::U2048;
type DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE = typenum::U33;
type MAX_PROPOSER_SLASHINGS = typenum::U16;
type MAX_ATTESTER_SLASHINGS = typenum::U2;
type MAX_ATTESTATIONS = typenum::U128;
type MAX_DEPOSITS = typenum::U16;
type MAX_VOLUNTARY_EXITS = typenum::U16;


#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ForkData {
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
//     # LMD GHOST vote
    pub beacon_block_root: Root,
//    # FFG vote
    pub source: Checkpoint,
    pub target: Checkpoint
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
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
    pub deposit_root: Root,
    pub deposit_count: u64,
    pub block_hash: Hash32,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct DepositData {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
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
    pub epoch: Epoch,  // Earliest epoch when voluntary exit can be processed
    pub validator_index: ValidatorIndex,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone)]
pub struct Attestation {
    pub aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
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
    pub randao_reveal: BLSSignature,
    pub eth1_data: Eth1Data,  // Eth1 data vote
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
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
pub struct SigningData {
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

fn secure_sign_block(pk_hex: String, block: BeaconBlock, domain: Domain) -> BLSSignature {
	// let previous_block = read_block();
	// // The block slot number must be strictly increasing to prevent slashing
	// assert!(block.slot > previous_block.slot);
	// write_block(block.clone());

    // let sk = keys::read_key(&pk_hex).expect("Couldn't fetch pk");

    // let root: Root = compute_signing_root(block, domain);

    // let sig = sk.sign(&root, keys::CIPHER_SUITE, &[]);

    // <_>::from(sig.to_bytes().to_vec())
    unimplemented!()
}

fn secure_sign_attestation(pk_hex: String, attestation_data: AttestationData, domain: Domain) -> BLSSignature {
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
    unimplemented!()
}

fn secure_sign_randao(pk_hex: String, epoch: Epoch, domain: Domain) -> BLSSignature {
    // let sk = keys::read_key(&pk_hex).expect("Couldn't fetch pk");

    // let root: Root = compute_signing_root(epoch, domain);

    // let sig = sk.sign(&root, keys::CIPHER_SUITE, &[]);

    // <_>::from(sig.to_bytes().to_vec())
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let bb = BeaconBlock::default(); 

        println!("{:?}", bb);
        let bytes = bb.as_ssz_bytes();
        println!("{:?}", bytes);
        println!("{:?}", BeaconBlock::from_ssz_bytes(&bytes).unwrap());
    }

    #[test]
    fn test_secure_sign_randao() {
        let pk_hex = String::from("8b17b1964fdfa87e8f172b09123f0e12cbc8195ee709bfb16545c7da2d98c9ab628ea74e786be0c08566efd366795a6a");
        let epoch = 123;
        let domain = Domain {  };
        secure_sign_randao(pk_hex, epoch, domain);
    }
}