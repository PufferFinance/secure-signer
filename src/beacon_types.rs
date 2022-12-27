use serde::{Deserialize, Serialize};
use serde::ser::{Serializer, SerializeStruct};
use serde::de::Error;
use serde::{Deserializer};
// use serde::de::Deserializer;
// use serde::de::value::Error;
use serde_hex::{SerHex, StrictPfx, CompactPfx};
use anyhow::{Result, Context, bail};

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, typenum, BitList, Bitfield, BitVector};

/// Types
pub type Bytes4  = [u8; 4];
pub type Bytes32 = [u8; 32];
pub type Bytes20 = FixedVector<u8, typenum::U20>;
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
pub type Domain = Bytes32;
pub type ExecutionAddress = Bytes20;

// typenums for specifying the length of FixedVector
pub type MAX_VALIDATORS_PER_COMMITTEE = typenum::U2048;
pub type DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE = typenum::U33;
pub type MAX_PROPOSER_SLASHINGS = typenum::U16;
pub type MAX_ATTESTER_SLASHINGS = typenum::U2;
pub type MAX_ATTESTATIONS = typenum::U128;
pub type MAX_DEPOSITS = typenum::U16;
pub type MAX_VOLUNTARY_EXITS = typenum::U16;

pub type SYNC_COMMITTEE_SIZE = typenum::U512;
pub type SYNC_COMMITTEE_SUBNET_COUNT = typenum::U4;
pub type SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT = typenum::U128;  // 512 / 4

pub const DOMAIN_BEACON_PROPOSER:                DomainType = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'
pub const DOMAIN_BEACON_ATTESTER:                DomainType = [1_u8, 0_u8, 0_u8, 0_u8]; // '0x01000000'
pub const DOMAIN_RANDAO:                         DomainType = [2_u8, 0_u8, 0_u8, 0_u8]; // '0x02000000'
pub const DOMAIN_DEPOSIT:                        DomainType = [3_u8, 0_u8, 0_u8, 0_u8]; // '0x03000000'
pub const DOMAIN_VOLUNTARY_EXIT:                 DomainType = [4_u8, 0_u8, 0_u8, 0_u8]; // '0x04000000'
pub const DOMAIN_SELECTION_PROOF:                DomainType = [5_u8, 0_u8, 0_u8, 0_u8]; // '0x05000000'
pub const DOMAIN_AGGREGATE_AND_PROOF:            DomainType = [6_u8, 0_u8, 0_u8, 0_u8]; // '0x06000000'
pub const DOMAIN_SYNC_COMMITTEE:                 DomainType = [7_u8, 0_u8, 0_u8, 0_u8]; // '0x07000000'
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [8_u8, 0_u8, 0_u8, 0_u8]; // '0x08000000'
pub const DOMAIN_CONTRIBUTION_AND_PROOF:         DomainType = [9_u8, 0_u8, 0_u8, 0_u8]; // '0x09000000'
pub const DOMAIN_APPLICATION_MASK:               DomainType = [0_u8, 0_u8, 0_u8, 1_u8]; // '0x00000001'
pub const DOMAIN_APPLICATION_BUILDER:            DomainType = [0_u8, 0_u8, 0_u8, 1_u8]; // '0x00000001'

pub const GENESIS_FORK_VERSION: Version = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'
pub const SLOTS_PER_EPOCH: u64 = 32;

pub fn from_bls_pk_hex<'de, D>(deserializer: D) -> Result<BLSPubkey, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_bls_pk_hex");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    println!("hex_str: {:?}", hex_str);
    // let bytes = hex::decode(hex_str).expect("failed to deserialize");
    let bytes = match &hex_str[0..2] { 
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize")
    };
    println!("bytes: {:?}", bytes);
    let pk: BLSPubkey = FixedVector::from(bytes);
    Ok(pk)
}

pub fn from_bls_sig_hex<'de, D>(deserializer: D) -> Result<BLSSignature, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_bls_sig_hex");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] { 
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize")
    };
    let pk: BLSSignature = FixedVector::from(bytes);
    Ok(pk)
}

pub fn from_address_hex<'de, D>(deserializer: D) -> Result<ExecutionAddress, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_address_hex");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] { 
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize")
    };
    let addr: ExecutionAddress = FixedVector::from(bytes);
    Ok(addr)
}

pub fn from_hex_to_bitlist<'de, D>(deserializer: D) -> Result<BitList<MAX_VALIDATORS_PER_COMMITTEE>, D::Error>
where
    D: Deserializer<'de>,
{
    println!("in from_hex_to_bitlist");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] { 
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize")
    };
    unimplemented!()
    // match BitList::from_bytes(bytes) {
    //     Ok(agg_bits) => Ok(agg_bits),
    //     Err(e) => Err(D::Error::TrailingCharacters)
    // }
    // let agg_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE> = match BitList::from_bytes(bytes) {
    //     Ok(agg_bits) => agg_bits,
    //     Err(e) => bail!("asdfa"),
    // }
    // Ok(agg_bits)
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
/// used by Web3Signer type = "RANDAO_REVEAL"
pub struct RandaoReveal {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub epoch: Epoch
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attestationdata
/// used by Web3Signer type = "ATTESTATION"
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
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// used by Web3Signer type = "DEPOSIT"
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
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntaryexit
/// used by Web3Signer type = "VOLUNTARY_EXIT"
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
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// used by Web3Signer type = "VALIDATOR_REGISTRATION"
pub struct ValidatorRegistration { 
    #[serde(deserialize_with = "from_address_hex")]
    pub fee_recipient: ExecutionAddress, 
    pub gas_limit: u64,  
    pub timestamp: u64, 
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone)]
pub struct Attestation {
    #[serde(deserialize_with = "from_hex_to_bitlist")]
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
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblock
/// used by Web3Signer type = "BLOCK"
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
    pub object_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub domain: Domain,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregateandproof
/// used by Web3Signer type = "AGGREGATE_AND_PROOF"
pub struct AggregateAndProof {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    // get_slot_signature(state, aggregate.data.slot, privkey)
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub selection_proof: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteemessage
/// used by Web3Signer type = "SYNC_COMMITTEE_MESSAGE"
/// TODO: Eth spec's container differs from W3S API
pub struct SyncCommitteeMessage {
    // Slot to which this contribution pertains
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot,
    // Block root for this signature
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // Index of the validator that produced this signature
    #[serde(with = "SerHex::<CompactPfx>")]
    pub validator_index: ValidatorIndex,
    // Signature by the validator over the block root of `slot`
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteecontribution
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct SyncCommitteeContribution {
    // Slot to which this contribution pertains
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot,
    // Block root for this contribution
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // The subcommittee this contribution pertains to out of the broader sync committee
    #[serde(with = "SerHex::<CompactPfx>")]
    pub subcommittee_index: u64,
    // A bit is set if a signature from the validator at the corresponding
    // index in the subcommittee is present in the aggregate `signature`.
    // aggregation_bits: Bitvector[SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT]
    pub aggregation_bits: BitVector<SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT>,
    // Signature by the validator(s) over the block root of `slot`
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#contributionandproof
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct ContributionAndProof {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub selection_proof: BLSSignature,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#syncaggregatorselectiondata
/// used by Web3Signer type = "SYNC_COMMITTEE_SELECTION_PROOF"
pub struct SyncAggregatorSelectionData {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot, 
    #[serde(with = "SerHex::<CompactPfx>")]
    pub subcommittee_index: u64,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize, Encode, Decode, Clone, Default)]
/// used by Web3Signer type = "AGGREGATION_SLOT"
pub struct AggregationSlot {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub slot: Slot, 
}

#[cfg(test)]
mod spec_tests {
    use super::*;
    use crate::keys;

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
        assert_eq!(dd.amount, 3735928559); // 0xdeadbeef

        let got_pk = dd.pubkey;
        let got_pk_hex = hex::encode(&got_pk[..]);
        let got_pk = keys::bls_pk_from_hex(got_pk_hex)?;
        
        let got_sig = dd.signature;
        let got_sig_hex = hex::encode(&got_sig[..]);
        let got_sig = keys::bls_sig_from_hex(got_sig_hex)?;
        keys::verify_bls_sig(got_sig, got_pk, b"hello world")
    }
}

