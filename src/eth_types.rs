use serde::{Deserialize, Deserializer, Serialize};
use serde_hex::{SerHex, StrictPfx};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, BitVector, FixedVector};
use tree_hash_derive::TreeHash;

/// Types
pub type Bytes4 = [u8; 4];
pub type Bytes32 = [u8; 32];
pub type Bytes20 = FixedVector<u8, typenum::U20>;
pub type Bytes48 = FixedVector<u8, typenum::U48>;
pub type Bytes96 = FixedVector<u8, typenum::U96>;
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

// typenums for specifying the length of FixedVector
pub type MAX_VALIDATORS_PER_COMMITTEE = typenum::U2048;
pub type DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE = typenum::U33;
pub type MAX_PROPOSER_SLASHINGS = typenum::U16;
pub type MAX_ATTESTER_SLASHINGS = typenum::U2;
pub type MAX_ATTESTATIONS = typenum::U128;
pub type MAX_DEPOSITS = typenum::U16;
pub type MAX_VOLUNTARY_EXITS = typenum::U16;

// Domains
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

// altair
pub type SYNC_COMMITTEE_SIZE = typenum::U512;
pub type SYNC_COMMITTEE_SUBNET_COUNT = typenum::U4;
pub type SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT = typenum::U128; // 512 / 4

// bellatrix
pub type MAX_EXTRA_DATA_BYTES = typenum::U32;
pub type MAX_TRANSACTIONS_PER_PAYLOAD = typenum::U1048576;
pub type BYTES_PER_LOGS_BLOOM = typenum::U256;
pub type MAX_BYTES_PER_TRANSACTION = typenum::U1073741824;
pub type Transaction = FixedVector<u8, MAX_BYTES_PER_TRANSACTION>;

// capella
pub type MAX_BLS_TO_EXECUTION_CHANGES = typenum::U16;
pub type MAX_WITHDRAWALS_PER_PAYLOAD = typenum::U16;

// Custom deserializers
pub fn from_bls_pk_hex<'de, D>(deserializer: D) -> Result<BLSPubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] {
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize"),
    };
    println!("bytes: {:?}", bytes);
    let pk: BLSPubkey = FixedVector::from(bytes);
    Ok(pk)
}

pub fn from_bls_sig_hex<'de, D>(deserializer: D) -> Result<BLSSignature, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] {
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize"),
    };
    let pk: BLSSignature = FixedVector::from(bytes);
    Ok(pk)
}

pub fn from_address_hex<'de, D>(deserializer: D) -> Result<ExecutionAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    let bytes = match &hex_str[0..2] {
        "0x" => hex::decode(&hex_str[2..]).expect("failed to deserialize"),
        _ => hex::decode(hex_str).expect("failed to deserialize"),
    };
    let addr: ExecutionAddress = FixedVector::from(bytes);
    Ok(addr)
}

pub fn from_u64_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    Ok(u64::from_str_radix(hex_str, 10).expect("not a decimal"))
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
    #[serde(deserialize_with = "from_u64_string")]
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
    #[serde(deserialize_with = "from_u64_string")]
    pub epoch: Epoch,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub root: Root,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// used by Web3Signer type = "RANDAO_REVEAL"
pub struct RandaoReveal {
    #[serde(deserialize_with = "from_u64_string")]
    pub epoch: Epoch,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#attestationdata
/// used by Web3Signer type = "ATTESTATION"
pub struct AttestationData {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(deserialize_with = "from_u64_string")]
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
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(deserialize_with = "from_u64_string")]
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
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct IndexedAttestation {
    pub attesting_indices: FixedVector<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(deserialize_with = "from_bls_sig_hex")]
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
    #[serde(deserialize_with = "from_u64_string")]
    pub deposit_count: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub block_hash: Hash32,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// used by Web3Signer type = "DEPOSIT"
pub struct DepositMessage {
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub withdrawal_credentials: Bytes32,
    #[serde(deserialize_with = "from_u64_string")]
    pub amount: Gwei,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// used by Web3Signer type = "DEPOSIT"
pub struct DepositData {
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub withdrawal_credentials: Bytes32,
    #[serde(deserialize_with = "from_u64_string")]
    pub amount: Gwei,
    #[serde(deserialize_with = "from_bls_sig_hex")]
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
    #[serde(deserialize_with = "from_u64_string")]
    pub epoch: Epoch, // Earliest epoch when voluntary exit can be processed
    #[serde(deserialize_with = "from_u64_string")]
    pub validator_index: ValidatorIndex,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// used by Web3Signer type = "VALIDATOR_REGISTRATION"
pub struct ValidatorRegistration {
    #[serde(deserialize_with = "from_address_hex")]
    pub fee_recipient: ExecutionAddress,
    #[serde(deserialize_with = "from_u64_string")]
    pub gas_limit: u64,
    #[serde(deserialize_with = "from_u64_string")]
    pub timestamp: u64,
    #[serde(deserialize_with = "from_bls_pk_hex")]
    pub pubkey: BLSPubkey,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct Attestation {
    pub aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    pub data: AttestationData,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
pub struct BeaconBlockBody {
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub randao_reveal: BLSSignature,
    pub eth1_data: Eth1Data, // Eth1 data vote
    #[serde(with = "SerHex::<StrictPfx>")]
    pub graffiti: Bytes32, // Arbitrary data
    // Operations,
    pub proposer_slashings: FixedVector<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    pub attester_slashings: FixedVector<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    pub attestations: FixedVector<Attestation, MAX_ATTESTATIONS>,
    pub deposits: FixedVector<Deposit, MAX_DEPOSITS>,
    pub voluntary_exits: FixedVector<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblock
/// used by Web3Signer type = "BLOCK" for phase 0 backward compatibility.
pub struct BeaconBlock {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(deserialize_with = "from_u64_string")]
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
    #[serde(deserialize_with = "from_u64_string")]
    pub index: WithdrawalIndex,
    #[serde(deserialize_with = "from_u64_string")]
    pub validator_index: ValidatorIndex,
    #[serde(deserialize_with = "from_address_hex")]
    pub address: ExecutionAddress,
    #[serde(deserialize_with = "from_u64_string")]
    pub amount: Gwei,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregateandproof
/// used by Web3Signer type = "AGGREGATE_AND_PROOF"
pub struct AggregateAndProof {
    #[serde(deserialize_with = "from_u64_string")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub selection_proof: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteemessage
/// used by Web3Signer type = "SYNC_COMMITTEE_MESSAGE"
/// Web3Signer's API differs from the ETH2 spec by ommitting the validator_index and signature fields as they are not necessary to run get_sync_committee_message(). We are following this convention for compatibility.
pub struct SyncCommitteeMessage {
    // Slot to which this contribution pertains
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    // Block root for this signature
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // -- begin difference from ETH2 spec --
    // // Index of the validator that produced this signature
    // #[serde(with = "SerHex::<CompactPfx>")]
    // pub validator_index: ValidatorIndex,
    // // Signature by the validator over the block root of `slot`
    // #[serde(deserialize_with = "from_bls_sig_hex")]
    // pub signature: BLSSignature,
    // -- end difference from ETH2 spec --
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteecontribution
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct SyncCommitteeContribution {
    // Slot to which this contribution pertains
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    // Block root for this contribution
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Root,
    // The subcommittee this contribution pertains to out of the broader sync committee
    #[serde(deserialize_with = "from_u64_string")]
    pub subcommittee_index: u64,
    // A bit is set if a signature from the validator at the corresponding
    // index in the subcommittee is present in the aggregate `signature`.
    pub aggregation_bits: BitVector<SYNC_COMMITTEE_SIZE_BY_SYNC_COMMITTEE_SUBNET_COUNT>,
    // Signature by the validator(s) over the block root of `slot`
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub signature: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#contributionandproof
/// used by Web3Signer type = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
pub struct ContributionAndProof {
    #[serde(deserialize_with = "from_u64_string")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution,
    #[serde(deserialize_with = "from_bls_sig_hex")]
    pub selection_proof: BLSSignature,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#syncaggregatorselectiondata
/// used by Web3Signer type = "SYNC_COMMITTEE_SELECTION_PROOF"
pub struct SyncAggregatorSelectionData {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
    #[serde(deserialize_with = "from_u64_string")]
    pub subcommittee_index: u64,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode, TreeHash, Clone, Default)]
/// used by Web3Signer type = "AGGREGATION_SLOT"
pub struct AggregationSlot {
    #[serde(deserialize_with = "from_u64_string")]
    pub slot: Slot,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockRequest {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub block: BeaconBlock,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockV2Request {
    pub fork_info: ForkInfo,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub signingRoot: Root,
    pub beacon_block: BlockV2RequestWrapper,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlockV2RequestWrapper {
    pub version: String,
    pub block_header: BeaconBlockHeader,
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
    pub randao_reveal: RandaoReveal,
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
    BLOCK(BlockRequest),
    BLOCK_V2(BlockV2Request),
    ATTESTATION(AttestationRequest),
    RANDAO_REVEAL(RandaoRevealRequest),
    AGGREGATE_AND_PROOF(AggregateAndProofRequest),
    AGGREGATION_SLOT(AggregationSlotRequest),
    DEPOSIT(DepositRequest),
    VOLUNTARY_EXIT(VoluntaryExitRequest),
    SYNC_COMMITTEE_MESSAGE(SyncCommitteeMessageRequest),
    SYNC_COMMITTEE_SELECTION_PROOF(SyncCommitteeSelectionProofRequest),
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(SyncCommitteeContributionAndProofRequest),
    VALIDATOR_REGISTRATION(ValidatorRegistrationRequest),

    // lower case
    block(BlockRequest),
    block_v2(BlockV2Request),
    attestation(AttestationRequest),
    randao_reveal(RandaoRevealRequest),
    aggregate_and_proof(AggregateAndProofRequest),
    aggregation_slot(AggregationSlotRequest),
    deposit(DepositRequest),
    voluntary_exit(VoluntaryExitRequest),
    sync_committee_message(SyncCommitteeMessageRequest),
    sync_committee_selection_proof(SyncCommitteeSelectionProofRequest),
    sync_committee_contribution_and_proof(SyncCommitteeContributionAndProofRequest),
    validator_registration(ValidatorRegistrationRequest),
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use anyhow::Result;

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
        assert_eq!(v.genesis_validators_root, [4, 112, 0, 7, 250, 188, 130, 130, 100, 74, 237, 109, 28, 124, 158, 33, 211, 138, 3, 160, 196, 186, 25, 63, 58, 254, 66, 136, 36, 179, 166, 115]);
        assert_eq!(hex::encode(v.genesis_validators_root), "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673");
        Ok(())
    }

    #[test]
    fn test_deserialize_deposit_message() -> Result<()> {
        let req = format!(r#"
            {{
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18",
                "withdrawal_credentials": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
                "amount":"10000"
            }}"#);

        let dd: DepositMessage = serde_json::from_str(&req)?;
        assert_eq!(dd.withdrawal_credentials, [4, 112, 0, 7, 250, 188, 130, 130, 100, 74, 237, 109, 28, 124, 158, 33, 211, 138, 3, 160, 196, 186, 25, 63, 58, 254, 66, 136, 36, 179, 166, 115]);
        assert_eq!(dd.amount, 10000); 
        Ok(())
    }

    #[test]
    fn test_deserialize_validator_registration() -> Result<()> {
        let req = format!(r#"
        {{
            "type": "VALIDATOR_REGISTRATION",
            "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
            "validator_registration": {{
                "fee_recipient": "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "gas_limit": "30000000",
                "timestamp":"100",
                "pubkey": "0x8349434ad0700e79be65c0c7043945df426bd6d7e288c16671df69d822344f1b0ce8de80360a50550ad782b68035cb18"
            }}
        }}"#);
        let v: ValidatorRegistrationRequest = serde_json::from_str(&req).unwrap();
        assert_eq!(v.signingRoot, [19, 157, 89, 219, 177, 119, 15, 220, 88, 47, 247, 81, 147, 114, 3, 82, 204, 199, 97, 49, 227, 122, 198, 157, 12, 16, 231, 65, 111, 63, 48, 80]);
        assert_eq!(v.validator_registration.gas_limit, 30000000);
        assert_eq!(v.validator_registration.timestamp, 100);
        assert_eq!(v.validator_registration.fee_recipient[..], [42_u8; 20]);
        assert_eq!(v.validator_registration.pubkey[..], [131, 73, 67, 74, 208, 112, 14, 121, 190, 101, 192, 199, 4, 57, 69, 223, 66, 107, 214, 215, 226, 136, 193, 102, 113, 223, 105, 216, 34, 52, 79, 27, 12, 232, 222, 128, 54, 10, 80, 85, 10, 215, 130, 182, 128, 53, 203, 24]);
        Ok(())
    }
}
