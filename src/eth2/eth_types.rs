use std::str::FromStr;

use num_bigint::BigUint;
use serde::de::{self, Deserializer};
use serde::ser::{self, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use serde_utils::quoted_u64;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, BitVector, FixedVector, VariableList};
use std::fmt::{self, Debug};
use tree_hash_derive::TreeHash;

use crate::strip_0x_prefix;

/// Types
pub type Bytes4 = [u8; 4];
pub type Bytes32 = [u8; 32];
pub type Bytes20 = FixedVector<u8, typenum::U20>;
pub type Bytes48 = FixedVector<u8, typenum::U48>;
pub type Bytes96 = FixedVector<u8, typenum::U96>;
pub type U256 = FixedVector<u64, typenum::U4>;
pub type Hash32 = Bytes32;
pub type Slot = u64;
pub type Epoch = u64;
pub type CommitteeIndex = u64;
pub type ValidatorIndex = u64;
pub type WithdrawalIndex = u64;
pub type Root = Bytes32;
pub type BLSSignature = Bytes96;
pub type BLSPubkey = Bytes48;
pub type Version = Bytes4;
pub type Gwei = u64;
pub type DomainType = Bytes4;
pub type Domain = Bytes32;
pub type ExecutionAddress = Bytes20;
pub type KZGCommitment = Bytes48;

// #[derive(Clone, Encode, Decode)]
// pub struct KZGCommitment {
//     pub data: Bytes48,
// }

// impl TreeHashTrait for KZGCommitment {
//     fn tree_hash_type() -> tree_hash::TreeHashType {
//         <FixedVector<u8, typenum::U48> as TreeHashTrait>::tree_hash_type()
//     }

//     fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
//         self.data.tree_hash_packed_encoding()
//     }

//     fn tree_hash_packing_factor() -> usize {
//         <FixedVector<u8, typenum::U48> as TreeHashTrait>::tree_hash_packing_factor()
//     }

//     fn tree_hash_root(&self) -> tree_hash::Hash256 {
//         self.data.tree_hash_root()
//     }
// }

// impl FromStr for KZGCommitment {
//     type Err = String;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         if let Some(stripped) = s.strip_prefix("0x") {
//             let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
//             if bytes.len() == 48 {
//                 let mut kzg_commitment_bytes = [0; 48];
//                 kzg_commitment_bytes[..].copy_from_slice(&bytes);
//                 Ok(Self {
//                     data: kzg_commitment_bytes.to_vec().into(),
//                 })
//             } else {
//                 Err(format!(
//                     "InvalidByteLength: got {}, expected {}",
//                     bytes.len(),
//                     48
//                 ))
//             }
//         } else {
//             Err("must start with 0x".to_string())
//         }
//     }
// }

// impl Serialize for KZGCommitment {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         serializer.serialize_str(&format!("{:?}", self))
//     }
// }

// impl<'de> Deserialize<'de> for KZGCommitment {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let string = String::deserialize(deserializer)?;
//         Self::from_str(&string).map_err(serde::de::Error::custom)
//     }
// }

// impl Debug for KZGCommitment {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", serde_utils::hex::encode(self.data.as_ssz_bytes()))
//     }
// }

// typenums for specifying the length of FixedVector
#[allow(non_camel_case_types)]
pub type MAX_VALIDATORS_PER_COMMITTEE = typenum::U2048;
#[allow(non_camel_case_types)]
pub type DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE = typenum::U33;
#[allow(non_camel_case_types)]
pub type MAX_PROPOSER_SLASHINGS = typenum::U16;
#[allow(non_camel_case_types)]
pub type MAX_ATTESTER_SLASHINGS = typenum::U2;
#[allow(non_camel_case_types)]
pub type MAX_ATTESTATIONS = typenum::U128;
#[allow(non_camel_case_types)]
pub type MAX_DEPOSITS = typenum::U16;
#[allow(non_camel_case_types)]
pub type MAX_VOLUNTARY_EXITS = typenum::U16;

// Domains
pub const DOMAIN_BEACON_PROPOSER: DomainType = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'
pub const DOMAIN_BEACON_ATTESTER: DomainType = [1_u8, 0_u8, 0_u8, 0_u8]; // '0x01000000'
pub const DOMAIN_RANDAO: DomainType = [2_u8, 0_u8, 0_u8, 0_u8]; // '0x02000000'
pub const DOMAIN_DEPOSIT: DomainType = [3_u8, 0_u8, 0_u8, 0_u8]; // '0x03000000'
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [4_u8, 0_u8, 0_u8, 0_u8]; // '0x04000000'
pub const DOMAIN_SELECTION_PROOF: DomainType = [5_u8, 0_u8, 0_u8, 0_u8]; // '0x05000000'
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [6_u8, 0_u8, 0_u8, 0_u8]; // '0x06000000'
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [7_u8, 0_u8, 0_u8, 0_u8]; // '0x07000000'
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [8_u8, 0_u8, 0_u8, 0_u8]; // '0x08000000'
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [9_u8, 0_u8, 0_u8, 0_u8]; // '0x09000000'
pub const DOMAIN_APPLICATION_MASK: DomainType = [0_u8, 0_u8, 0_u8, 1_u8]; // '0x00000001'
pub const DOMAIN_APPLICATION_BUILDER: DomainType = [0_u8, 0_u8, 0_u8, 1_u8]; // '0x00000001'

pub const GENESIS_FORK_VERSION: Version = [0_u8, 0_u8, 0_u8, 0_u8]; // '0x00000000'
pub const SLOTS_PER_EPOCH: u64 = 32;

// altair
#[allow(non_camel_case_types)]
pub type SYNC_COMMITTEE_SIZE = typenum::U512;
#[allow(non_camel_case_types)]
pub type SYNC_COMMITTEE_SUBNET_COUNT = typenum::U4;
#[allow(non_camel_case_types)]
pub type SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT = typenum::U128; // 512 / 4

// bellatrix
#[allow(non_camel_case_types)]
pub type MAX_EXTRA_DATA_BYTES = typenum::U32;
#[allow(non_camel_case_types)]
pub type MAX_TRANSACTIONS_PER_PAYLOAD = typenum::U1048576;
#[allow(non_camel_case_types)]
pub type BYTES_PER_LOGS_BLOOM = typenum::U256;
#[allow(non_camel_case_types)]
pub type MAX_BYTES_PER_TRANSACTION = typenum::U1073741824;
#[allow(non_camel_case_types)]
pub type Transaction = VariableList<u8, MAX_BYTES_PER_TRANSACTION>;

// capella
#[allow(non_camel_case_types)]
pub type MAX_BLS_TO_EXECUTION_CHANGES = typenum::U16;
#[allow(non_camel_case_types)]
pub type MAX_WITHDRAWALS_PER_PAYLOAD = typenum::U16;

// deneb
#[allow(non_camel_case_types)]
pub type MAX_BLOB_COMMITMENTS_PER_BLOCK = typenum::U4096;

// Custom deserializers
pub fn from_hex_to_ssz_type<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: From<Vec<u8>>,
{
    println!("Inside hex deserialization!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let hex_str: &str = strip_0x_prefix!(hex_str);
    let bytes = match hex::decode(hex_str) {
        Ok(bs) => bs,
        Err(e) => return Err(de::Error::custom(format!("Not valid hex: {:?}", e))),
    };
    Ok(T::from(bytes))
}

pub fn to_hex_from_ssz_type<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Encode,
{
    let hex_string = "0x".to_string() + &hex::encode(data.as_ssz_bytes());
    serializer.serialize_str(&hex_string)
}

pub fn from_hex_vec_to_ssz_type<'de, D, N>(
    deserializer: D,
) -> Result<VariableList<FixedVector<u8, typenum::U48>, N>, D::Error>
where
    D: Deserializer<'de>,
    N: typenum::Unsigned,
{
    let mut res: Vec<FixedVector<u8, typenum::U48>> = Vec::new();
    println!("Inside blob deserialization!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    let hex_string_vec: Vec<String> =
        Vec::deserialize(deserializer).expect("Failed to deserialize");
    println!("After hex deserialization!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    // let hex_string_vec = opt.unwrap_or_default();

    for hex_str in hex_string_vec {
        let hex_str: &str = strip_0x_prefix!(hex_str);
        let bytes = match hex::decode(hex_str) {
            Ok(bs) => bs,
            Err(e) => return Err(de::Error::custom(format!("Not valid hex: {:?}", e))),
        };
        println!("<================== KZG Blob Bytes: {:?}", bytes.clone());
        res.push(FixedVector::<u8, typenum::U48>::new(bytes).unwrap());
    }
    Ok(VariableList::new(res).unwrap())
}

pub fn to_hex_vec_from_ssz_type<S>(
    data: &VariableList<FixedVector<u8, typenum::U48>, typenum::U4096>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    println!("Inside blob serialization!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    let mut res: Vec<String> = Vec::new();
    for d in data {
        let hex_string = "0x".to_string() + &hex::encode(d.as_ssz_bytes());
        res.push(hex_string);
    }
    let mut seq = serializer.serialize_seq(Some(res.len()))?;
    for element in res {
        seq.serialize_element(&element)?;
    }
    seq.end()
}

pub fn from_hex_to_ssz_bits_type<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Decode,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let hex_str: &str = strip_0x_prefix!(hex_str);
    let bytes = match hex::decode(hex_str) {
        Ok(bs) => bs,
        Err(e) => return Err(de::Error::custom(format!("Not valid hex: {:?}", e))),
    };
    match T::from_ssz_bytes(&bytes.as_ssz_bytes()) {
        Ok(out) => Ok(out),
        Err(e) => {
            return Err(de::Error::custom(format!(
                "Filaed to deserialize hex string to BitList/BitVector: {:?}",
                e
            )))
        }
    }
}

pub fn from_u256_string<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let decimal_str = String::deserialize(deserializer)?;
    let big_uint = BigUint::parse_bytes(decimal_str.as_bytes(), 10);

    let bytes = match big_uint {
        Some(u) => u.to_u64_digits(),
        None => return Err(de::Error::custom("Invalid decimal string for U256")),
    };

    if bytes.len() != 4 {
        return Err(de::Error::custom(
            "Decimal string doesn't match the required length for U256",
        ));
    }

    let out: U256 = FixedVector::from(bytes);
    Ok(out)
}

pub fn to_u256_string<S>(num: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let out = BigUint::from_bytes_le(&num.as_ssz_bytes());
    serializer.serialize_str(&out.to_str_radix(10))
}

pub fn de_signing_root<'de, D>(deserializer: D) -> Result<Option<Root>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: &str = Deserialize::deserialize(deserializer)?;
    if hex_string.is_empty() {
        return Ok(None);
    }

    let bytes: Root = match SerHex::<StrictPfx>::from_hex(&hex_string) {
        Ok(bs) => bs,
        Err(e) => return Err(de::Error::custom(format!("Not valid hex: {:?}", e))),
    };
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    Ok(Some(array))
}

/// Assumes that calling struct will skip serializing if the option is none
pub fn se_signing_root<S>(value: &Option<Root>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v = match value {
        Some(v) => v,
        None => return Err(ser::Error::custom("Can't serialize None")),
    };
    let hex_string = hex::encode(v);
    serializer.serialize_str(&hex_string)
}

// Datatypes from ETH2 specs

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SigningData {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub object_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub domain: Domain,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
pub struct Fork {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub previous_version: Version,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub current_version: Version,
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct ForkData {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub current_version: Version,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Root,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
pub struct ForkInfo {
    pub fork: Fork,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Root,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct Checkpoint {
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub root: Root,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// used by Web3Signer type = "RANDAO_REVEAL"
pub struct RandaoReveal {
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attestationdata
/// used by Web3Signer type = "ATTESTATION"
pub struct AttestationData {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub index: CommitteeIndex,
    // LMD GHOST vote
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // FFG vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
/// used by Web3Signer type = "BLOCK_V2"
pub struct BeaconBlockHeader {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub proposer_index: ValidatorIndex,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub body_root: Root,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct IndexedAttestation {
    pub attesting_indices: VariableList<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct Eth1Data {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub deposit_root: Root,
    #[serde(with = "quoted_u64")]
    pub deposit_count: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub block_hash: Hash32,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// used by Web3Signer type = "DEPOSIT"
pub struct DepositMessage {
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub pubkey: BLSPubkey,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "quoted_u64")]
    pub amount: Gwei,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// used by Web3Signer type = "DEPOSIT"
pub struct DepositData {
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub pubkey: BLSPubkey,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "quoted_u64")]
    pub amount: Gwei,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature, // Signing over DepositMessage
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct Deposit {
    pub proof: FixedVector<Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE>, // Merkle path to deposit root
    pub data: DepositData,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntaryexit
/// used by Web3Signer type = "VOLUNTARY_EXIT"
pub struct VoluntaryExit {
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch, // Earliest epoch when voluntary exit can be processed
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#validatorregistrationv1
/// used by Web3Signer type = "VALIDATOR_REGISTRATION"
pub struct ValidatorRegistration {
    #[serde(deserialize_with = "from_hex_to_ssz_type")]
    #[serde(serialize_with = "to_hex_from_ssz_type")]
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "quoted_u64")]
    pub timestamp: u64,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub pubkey: BLSPubkey,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct Attestation {
    #[serde(
        deserialize_with = "from_hex_to_ssz_bits_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SyncAggregate {
    #[serde(
        deserialize_with = "from_hex_to_ssz_bits_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub sync_committee_bits: BitVector<SYNC_COMMITTEE_SIZE>,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub sync_committee_signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct BeaconBlockBody {
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub randao_reveal: BLSSignature,
    pub eth1_data: Eth1Data, // Eth1 data vote
    #[serde(with = "SerHex::<StrictPfx>")]
    pub graffiti: Bytes32, // Arbitrary data
    // Operations,
    pub proposer_slashings: VariableList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    pub attester_slashings: VariableList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    pub attestations: VariableList<Attestation, MAX_ATTESTATIONS>,
    pub deposits: VariableList<Deposit, MAX_DEPOSITS>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    pub sync_aggregate: SyncAggregate, // # [New in Altair]

    // https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#beaconblockbody
    pub execution_payload: ExecutionPayload, //   # [Modified in Deneb:EIP4844]

    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconblockbody
    pub bls_to_execution_changes:
        VariableList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>, // [New in Capella]

    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#beaconblockbody
    #[serde(
        deserialize_with = "from_hex_vec_to_ssz_type",
        serialize_with = "to_hex_vec_from_ssz_type"
    )]
    pub blob_kzg_commitments: VariableList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>, // [New in Deneb:EIP4844]
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct ExecutionPayload {
    // Execution block header fields
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_hash: Root,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub fee_recipient: ExecutionAddress, // 'beneficiary' in the yellow paper
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub receipts_root: Root,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub logs_bloom: FixedVector<u8, BYTES_PER_LOGS_BLOOM>,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub prev_randao: Root, // 'difficulty' in the yellow paper
    #[serde(with = "quoted_u64")]
    pub block_number: u64, // 'number' in the yellow paper
    #[serde(with = "quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "quoted_u64")]
    pub timestamp: u64,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub extra_data: VariableList<u8, MAX_EXTRA_DATA_BYTES>,
    #[serde(
        deserialize_with = "from_u256_string",
        serialize_with = "to_u256_string"
    )]
    pub base_fee_per_gas: U256,
    // Extra payload fields,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub block_hash: Root, // Hash of execution block
    pub transactions: VariableList<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>,
    pub withdrawals: VariableList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>, // [New in Capella]
    #[serde(with = "quoted_u64")]
    pub blob_gas_used: u64,                // [New in Deneb:EIP4844]
    #[serde(with = "quoted_u64")]
    pub excess_blob_gas: u64,              // [New in Deneb:EIP4844]
    #[serde(
        deserialize_with = "from_u256_string",
        serialize_with = "to_u256_string"
    )]
    pub excess_data_gas: U256, // according to the downloaded spec test vectors but not official ethereum specs.
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct BLSToExecutionChange {
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub from_bls_pubkey: BLSPubkey,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub to_execution_address: ExecutionAddress,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SignedBLSToExecutionChange {
    pub message: BLSToExecutionChange,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblock
/// used by Web3Signer type = "BLOCK" for phase 0 backward compatibility.
pub struct BeaconBlock {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub proposer_index: ValidatorIndex,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_root: Root,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#withdrawal
pub struct Withdrawal {
    #[serde(with = "quoted_u64")]
    pub index: WithdrawalIndex,
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub address: ExecutionAddress,
    #[serde(with = "quoted_u64")]
    pub amount: Gwei,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregateandproof
/// used by Web3Signer type = "AGGREGATE_AND_PROOF"
pub struct AggregateAndProof {
    #[serde(with = "quoted_u64")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub selection_proof: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteemessage
/// used by Web3Signer type = "SYNC_COMMITTEE_MESSAGE"
pub struct SyncCommitteeMessage {
    // Slot to which this contribution pertains
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    // Block root for this signature
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // Index of the validator that produced this signature
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    // Signature by the validator over the block root of `slot`
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteecontribution
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct SyncCommitteeContribution {
    // Slot to which this contribution pertains
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    // Block root for this contribution
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // The subcommittee this contribution pertains to out of the broader sync committee
    #[serde(with = "quoted_u64")]
    pub subcommittee_index: u64,
    // A bit is set if a signature from the validator at the corresponding
    // index in the subcommittee is present in the aggregate `signature`.
    #[serde(
        deserialize_with = "from_hex_to_ssz_bits_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub aggregation_bits: BitVector<SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT>,
    // Signature by the validator(s) over the block root of `slot`
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#contributionandproof
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct ContributionAndProof {
    #[serde(with = "quoted_u64")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution,
    #[serde(
        deserialize_with = "from_hex_to_ssz_type",
        serialize_with = "to_hex_from_ssz_type"
    )]
    pub selection_proof: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#syncaggregatorselectiondata
/// used by Web3Signer type = "SYNC_COMMITTEE_SELECTION_PROOF"
pub struct SyncAggregatorSelectionData {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub subcommittee_index: u64,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// used by Web3Signer type = "AGGREGATION_SLOT"
pub struct AggregationSlot {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct BlockRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct BlockV2Request {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub beacon_block: BlockV2RequestWrapper,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockV2RequestWrapper {
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct AttestationRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub attestation: AttestationData,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct RandaoRevealRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub randao_reveal: RandaoReveal,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct AggregateAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub aggregate_and_proof: AggregateAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct AggregationSlotRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub aggregation_slot: AggregationSlot,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct DepositRequest {
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub deposit: DepositMessage,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_fork_version: Version,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
/// Custom response to work with https://launchpad.ethereum.org/en/upload-deposit-data
pub struct DepositResponse {
    pub pubkey: String,
    pub withdrawal_credentials: String,
    pub amount: Gwei,
    pub signature: String, // Signing over DepositMessage
    pub deposit_message_root: String,
    pub deposit_data_root: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct VoluntaryExitRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub voluntary_exit: VoluntaryExit,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SyncCommitteeMessageRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    // pub sync_committee_message: SyncCommitteeMessage,
    pub sync_committee_message: SyncCommitteeMessageRequestWrapper,
}

#[derive(Deserialize, Serialize, Debug)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteemessage
/// used by Web3Signer type = "SYNC_COMMITTEE_MESSAGE"
/// Web3Signer's API differs from the ETH2 spec by ommitting the validator_index and signature fields as they are not necessary to run get_sync_committee_message().
/// We are following this convention for compatibility.
pub struct SyncCommitteeMessageRequestWrapper {
    // Slot to which this contribution pertains
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    // Block root for this signature
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SyncCommitteeSelectionProofRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub sync_aggregator_selection_data: SyncAggregatorSelectionData,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SyncCommitteeContributionAndProofRequest {
    pub fork_info: ForkInfo,
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub contribution_and_proof: ContributionAndProof,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct ValidatorRegistrationRequest {
    #[serde(default)]
    #[serde(deserialize_with = "de_signing_root")]
    #[serde(serialize_with = "se_signing_root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signingRoot: Option<Root>,
    pub validator_registration: ValidatorRegistration,
}

//////// TEST //////
#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct CustomKZG {
    #[serde(
        deserialize_with = "from_hex_vec_to_ssz_type",
        serialize_with = "to_hex_vec_from_ssz_type"
    )]
    pub data: VariableList<Bytes48, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

impl fmt::Display for BeaconBlockBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BeaconBlockBody blob_kzg_commitments: {:?} ",
            // self.randao_reveal,
            // self.eth1_data,
            // self.graffiti,
            // self.proposer_slashings,
            // self.attester_slashings,
            // self.attestations,
            // self.deposits,
            // self.voluntary_exits,
            // self.sync_aggregate,
            // self.execution_payload,
            // self.bls_to_execution_changes,
            self.blob_kzg_commitments
        )
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use anyhow::Result;

    //////// REMOVE LATER /////////

    // fn snappy_decode_file_to_eth_type<T: Decode + TreeHash>(path: &Path) -> Result<T> {
    //     let bytes = fs::read(path).with_context(|| format!("Unable to load {}", path.display()))?;
    //     let mut decoder = Decoder::new();
    //     let bytes = decoder
    //         .decompress_vec(&bytes)
    //         .with_context(|| format!("Error decoding snappy encoding for {}", path.display(),))?;
    //     match T::from_ssz_bytes(&bytes) {
    //         Ok(res) => Ok(res),
    //         Err(e) => bail!("Failed to decode to ssz type: {:?}", e),
    //     }
    // }

    #[test]
    fn test_deserialize_custom_kzg() -> Result<()> {
        let req = r#"
            {
                "data": ["0x7f82e0c1f7964445ecbcac74bc186724df0f7b2da6a67f2051e1457e155fc9a21f1b44d1a2a8910f0aadee0905b71007",
                "0x345bc9a138646b7dac7bd2e5d615cb15c240db5309e20f391cdc5e593dca384be69e6140a0758f1e0f0c5d010f0e409c",
                "0xb2c97b0d59487670503b518a51fb1dd7ebc18fa04f7a340188518af77164da34cd9b865956eeb4251bd0e16d2d2f4103",
                "0x604c092a784346ce44690d932eff0494d8aa9321f4f0fa935782e9a4b47739510560b246568a387ad945f3f5a6216e4b"]
            }"#;

        let v0 = hex::decode("7f82e0c1f7964445ecbcac74bc186724df0f7b2da6a67f2051e1457e155fc9a21f1b44d1a2a8910f0aadee0905b71007").unwrap();
        let v1 = hex::decode("345bc9a138646b7dac7bd2e5d615cb15c240db5309e20f391cdc5e593dca384be69e6140a0758f1e0f0c5d010f0e409c").unwrap();
        let v2 = hex::decode("b2c97b0d59487670503b518a51fb1dd7ebc18fa04f7a340188518af77164da34cd9b865956eeb4251bd0e16d2d2f4103").unwrap();
        let v3 = hex::decode("604c092a784346ce44690d932eff0494d8aa9321f4f0fa935782e9a4b47739510560b246568a387ad945f3f5a6216e4b").unwrap();

        let v: CustomKZG = serde_json::from_str(req)?;
        assert_eq!(v.data.len(), 4);
        assert_eq!(v.data[0], FixedVector::<u8, typenum::U48>::new(v0).unwrap());
        assert_eq!(v.data[1], FixedVector::<u8, typenum::U48>::new(v1).unwrap());
        assert_eq!(v.data[2], FixedVector::<u8, typenum::U48>::new(v2).unwrap());
        assert_eq!(v.data[3], FixedVector::<u8, typenum::U48>::new(v3).unwrap());

        // assert_eq!(
        //     v.data[0],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             127, 130, 224, 193, 247, 150, 68, 69, 236, 188, 172, 116, 188, 24, 103, 36,
        //             223, 15, 123, 45, 166, 127, 32, 81, 225, 69, 126, 21, 95, 201, 162, 31, 27, 68,
        //             209, 162, 168, 145, 15, 10, 173, 238, 9, 5, 183, 16, 7
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );
        // assert_eq!(
        //     v.data[1],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             52, 91, 201, 161, 56, 100, 107, 125, 172, 123, 210, 229, 214, 21, 203, 21, 194,
        //             64, 219, 83, 9, 226, 15, 57, 28, 220, 94, 89, 61, 202, 56, 75, 230, 158, 97,
        //             64, 160, 117, 143, 30, 15, 12, 93, 1, 15, 14, 64, 156
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );
        // assert_eq!(
        //     v.data[2],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             178, 201, 123, 13, 89, 72, 118, 112, 80, 59, 81, 138, 81, 251, 29, 215, 235,
        //             193, 143, 160, 79, 122, 52, 1, 136, 81, 138, 247, 113, 100, 218, 52, 205, 155,
        //             134, 89, 86, 238, 180, 37, 27, 208, 225, 109, 45, 47, 65, 3
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );
        // assert_eq!(
        //     v.data[3],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             96, 76, 9, 42, 120, 67, 70, 206, 68, 105, 13, 147, 46, 255, 4, 148, 216, 170,
        //             147, 33, 244, 240, 250, 147, 87, 46, 154, 75, 71, 55, 149, 16, 86, 11, 36, 101,
        //             104, 163, 135, 173, 148, 95, 63, 90, 98, 22, 228, 177
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );
        // assert_eq!(
        //     v.data[0],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             2, 32, 30, 60, 205, 61, 54, 174, 47, 60, 165, 220, 215, 152, 149, 48, 154, 72,
        //             185, 209, 171, 78, 36, 64, 240, 144, 192, 248, 240, 165, 176, 74, 244, 49, 56,
        //             246, 167, 84, 171, 26, 47, 252, 177, 223, 229, 46, 94, 170
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );

        // assert_eq!(
        //     v.data[1],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             159, 57, 3, 231, 90, 85, 26, 107, 68, 154, 198, 44, 12, 23, 167, 153, 133, 114,
        //             18, 211, 157, 97, 184, 30, 100, 174, 251, 74, 215, 4, 194, 248, 206, 100, 115,
        //             234, 117, 196, 155, 112, 21, 81, 99, 255, 179, 27, 197, 137
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );

        // assert_eq!(
        //     v.data[2],
        //     FixedVector::<u8, typenum::U48>::new(
        //         [
        //             121, 126, 116, 170, 94, 74, 253, 228, 17, 184, 58, 6, 31, 126, 23, 95, 135,
        //             241, 220, 206, 65, 100, 52, 5, 66, 79, 56, 60, 105, 134, 77, 121, 56, 98, 35,
        //             65, 117, 180, 91, 93, 253, 93, 248, 8, 81, 70, 245, 233
        //         ]
        //         .to_vec()
        //     )
        //     .unwrap()
        // );
        Ok(())
    }

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
        assert_eq!(v.epoch, 10);
        Ok(())
    }

    #[test]
    fn test_deserialize_fork_info() -> Result<()> {
        let req = r#"
            {
                "fork":{
                    "previous_version":"0x00000001",
                    "current_version":"0x00000001",
                    "epoch":"999"
                },
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            }"#;

        let v: ForkInfo = serde_json::from_str(req)?;
        assert_eq!(v.fork.previous_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.current_version, [0, 0, 0, 1]);
        assert_eq!(v.fork.epoch, 999);
        // python: list(bytes.fromhex('04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673'))
        assert_eq!(
            v.genesis_validators_root,
            [
                4, 112, 0, 7, 250, 188, 130, 130, 100, 74, 237, 109, 28, 124, 158, 33, 211, 138, 3,
                160, 196, 186, 25, 63, 58, 254, 66, 136, 36, 179, 166, 115
            ]
        );
        assert_eq!(
            hex::encode(v.genesis_validators_root),
            "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_deposit_message() -> Result<()> {
        let req = format!(
            r#"
            {{
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18",
                "withdrawal_credentials": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
                "amount":"10000"
            }}"#
        );

        let dd: DepositMessage = serde_json::from_str(&req)?;
        assert_eq!(
            dd.withdrawal_credentials,
            [
                4, 112, 0, 7, 250, 188, 130, 130, 100, 74, 237, 109, 28, 124, 158, 33, 211, 138, 3,
                160, 196, 186, 25, 63, 58, 254, 66, 136, 36, 179, 166, 115
            ]
        );
        assert_eq!(dd.amount, 10000);
        Ok(())
    }

    #[test]
    fn test_deserialize_validator_registration() -> Result<()> {
        let req = format!(
            r#"
        {{
            "type": "VALIDATOR_REGISTRATION",
            "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
            "validator_registration": {{
                "fee_recipient": "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "gas_limit": "30000000",
                "timestamp":"100",
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18"
            }}
        }}"#
        );
        let v: ValidatorRegistrationRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(
            v.signingRoot,
            Some([
                19, 157, 89, 219, 177, 119, 15, 220, 88, 47, 247, 81, 147, 114, 3, 82, 204, 199,
                97, 49, 227, 122, 198, 157, 12, 16, 231, 65, 111, 63, 48, 80
            ])
        );
        assert_eq!(v.validator_registration.gas_limit, 30000000);
        assert_eq!(v.validator_registration.timestamp, 100);
        assert_eq!(v.validator_registration.fee_recipient[..], [42_u8; 20]);
        assert_eq!(
            v.validator_registration.pubkey[..],
            [
                131, 73, 67, 74, 208, 112, 14, 121, 190, 101, 192, 199, 4, 57, 69, 223, 66, 107,
                214, 215, 226, 136, 193, 102, 113, 223, 105, 216, 34, 52, 79, 27, 12, 232, 222,
                128, 54, 10, 80, 85, 10, 215, 130, 182, 128, 53, 203, 24
            ]
        );
        Ok(())
    }
}
