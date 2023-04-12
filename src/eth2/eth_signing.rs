use super::eth_types::*;
use super::slash_protection;
use crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB;
use crate::crypto::bls_keys;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::Encode;
use std::fs;
use std::path::PathBuf;
use tree_hash::TreeHash;

use log::{debug, error, info};

/// Return the signing root for the corresponding signing data.
fn compute_signing_root<T: Encode + TreeHash>(ssz_object: T, domain: Domain) -> Root {
    let object_root = ssz_object.tree_hash_root().to_fixed_bytes();
    let sign_data = SigningData {
        object_root,
        domain,
    };
    sign_data.tree_hash_root().to_fixed_bytes()
}

/// Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
/// This is used primarily in signature domains to avoid collisions across forks/chains.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    let f = ForkData {
        current_version,
        genesis_validators_root,
    };
    f.tree_hash_root().to_fixed_bytes()
}

/// Return the epoch number at ``slot``.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_epoch_at_slot
pub fn compute_epoch_at_slot(slot: Slot) -> Epoch {
    slot / SLOTS_PER_EPOCH
}

/// Return the signature domain (fork version concatenated with domain type) of a message.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#get_domain
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_domain(fork_info: ForkInfo, domain_type: DomainType, epoch: Option<Epoch>) -> Domain {
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => fork_info.fork.epoch,
    };

    let fork_version = if epoch < fork_info.fork.epoch {
        fork_info.fork.previous_version
    } else {
        fork_info.fork.current_version
    };
    compute_domain(
        domain_type,
        Some(fork_version),
        Some(fork_info.genesis_validators_root),
    )
}

/// Return the domain for the ``domain_type`` and ``fork_version``.
pub fn compute_domain(
    domain_type: DomainType,
    fork_version: Option<Version>,
    genesis_validators_root: Option<Root>,
) -> Domain {
    let fv = match fork_version {
        Some(fv) => fv,
        None => GENESIS_FORK_VERSION,
    };

    let gvr = match genesis_validators_root {
        Some(gvr) => gvr,
        None => [0_u8; 32], // all bytes zero by default
    };
    let fork_data_root = compute_fork_data_root(fv, gvr);
    let mut d = [0_u8; 32]; // domain_type + fork_data_root[:28]
    domain_type.iter().enumerate().for_each(|(i, v)| d[i] = *v);
    d[4..32]
        .iter_mut()
        .zip(fork_data_root[0..28].iter())
        .for_each(|(src, dest)| *src = *dest);
    d
}

/// Reusable signing function that signs SSZ objects by fetching bls sk from memory
pub fn secure_sign<T: Encode + TreeHash>(
    pk_hex: String,
    msg: T,
    domain: Domain,
) -> Result<BLSSignature> {
    let root: Root = compute_signing_root(msg, domain);
    info!("Computed signingRoot: {:?}", hex::encode(root));
    let sig = bls_keys::bls_agg_sign_from_saved_sk(&pk_hex, &root)?;
    info!("Computed signature: {:?}", hex::encode(sig.to_bytes()));
    Ok(<_>::from(sig.to_bytes().to_vec()))
}

/// Slash-protected block proposing - bail statements prevent slashable offenses (phase0).
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
pub fn get_block_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    block: BeaconBlock,
) -> Result<BLSSignature> {
    // read previous slot from mem
    let mut sp = slash_protection::SlashingProtectionData::read(&pk_hex)?;
    let previous_block_slot = sp.get_latest_signed_block_slot();

    // The block slot number must be strictly increasing to prevent slashing
    if block.slot <= previous_block_slot {
        error!("Prevented slashable offense");
        bail!("block.slot <= previous_block_slot")
    }

    let domain = get_domain(
        fork_info,
        DOMAIN_BEACON_PROPOSER,
        Some(compute_epoch_at_slot(block.slot)),
    );

    let root: Root = compute_signing_root(block.clone(), domain.clone());
    let b = slash_protection::SignedBlockSlot {
        slot: block.slot,
        signing_root: Some(root),
    };
    // Save the new block slot to persistent memory
    sp.new_block(b, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
    sp.write()?;

    secure_sign(pk_hex, block, domain)
}

/// Slash-protected block proposing - bail statements prevent slashable offenses (phase0).
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
pub fn get_block_v2_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    block_header: BeaconBlockHeader,
) -> Result<BLSSignature> {
    // read previous slot from mem
    let mut sp = slash_protection::SlashingProtectionData::read(&pk_hex)?;
    let previous_block_slot = sp.get_latest_signed_block_slot();

    // The block slot number must be strictly increasing to prevent slashing
    if block_header.slot <= previous_block_slot {
        error!("Prevented slashable offense");
        bail!("block_header.slot <= previous_block_slot")
    }

    let domain = get_domain(
        fork_info,
        DOMAIN_BEACON_PROPOSER,
        Some(compute_epoch_at_slot(block_header.slot)),
    );

    let root: Root = compute_signing_root(block_header.clone(), domain.clone());
    let b = slash_protection::SignedBlockSlot {
        slot: block_header.slot,
        signing_root: Some(root),
    };
    // Save the new block slot to persistent memory
    sp.new_block(b, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
    sp.write()?;

    secure_sign(pk_hex, block_header, domain)
}

/// Slash-protected attestations - bail statements prevent slashable offenses.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregate-signature
pub fn get_attestation_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    attestation_data: AttestationData,
) -> Result<BLSSignature> {
    let mut sp = slash_protection::SlashingProtectionData::read(&pk_hex)?;
    let (prev_src_epoch, prev_tgt_epoch) = sp.get_latest_signed_attestation_epochs();

    // The attestation source epoch must be non-decreasing to prevent slashing
    if attestation_data.source.epoch < prev_src_epoch {
        error!("Prevented slashable offense");
        bail!("attestation_data.source.epoch < prev_src_epoch")
    }

    // The attestation target epoch must be strictly increasing to prevent slashing
    if attestation_data.target.epoch <= prev_tgt_epoch {
        error!("Prevented slashable offense");
        bail!("attestation_data.target.epoch <= prev_tgt_epoch")
    }

    // Sign the Attestation
    let domain = get_domain(
        fork_info,
        DOMAIN_BEACON_ATTESTER,
        Some(attestation_data.target.epoch),
    );

    let root: Root = compute_signing_root(attestation_data.clone(), domain.clone());
    let a = slash_protection::SignedAttestationEpochs {
        source_epoch: attestation_data.source.epoch,
        target_epoch: attestation_data.target.epoch,
        signing_root: Some(root),
    };
    // Save the new attestation data to persistent memory
    sp.new_attestation(a, ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
    sp.write()?;

    secure_sign(pk_hex, attestation_data, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#randao-reveal
pub fn get_epoch_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    epoch: Epoch,
) -> Result<BLSSignature> {
    let domain = get_domain(fork_info, DOMAIN_RANDAO, Some(epoch));
    secure_sign(pk_hex, epoch, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#attestation-aggregation
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_slot_signature(pk_hex: String, fork_info: ForkInfo, slot: Slot) -> Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(slot);
    let domain = get_domain(fork_info, DOMAIN_SELECTION_PROOF, Some(epoch));
    secure_sign(pk_hex, slot, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#broadcast-aggregate
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_aggregate_and_proof(
    pk_hex: String,
    fork_info: ForkInfo,
    aggregate_and_proof: AggregateAndProof,
) -> Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(aggregate_and_proof.aggregate.data.slot);
    let domain = get_domain(fork_info, DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
    secure_sign(pk_hex, aggregate_and_proof, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee-messages
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_sync_committee_message(
    pk_hex: String,
    fork_info: ForkInfo,
    sync_committee_message: SyncCommitteeMessage,
) -> Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(sync_committee_message.slot);
    let domain = get_domain(fork_info, DOMAIN_SYNC_COMMITTEE, Some(epoch));
    secure_sign(pk_hex, sync_committee_message.beacon_block_root, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_sync_committee_selection_proof(
    pk_hex: String,
    fork_info: ForkInfo,
    sync_aggregator_selection_data: SyncAggregatorSelectionData,
) -> Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(sync_aggregator_selection_data.slot);
    let domain = get_domain(
        fork_info,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        Some(epoch),
    );
    secure_sign(pk_hex, sync_aggregator_selection_data, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_contribution_and_proof_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    contribution_and_proof: ContributionAndProof,
) -> Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(contribution_and_proof.contribution.slot);
    let domain = get_domain(fork_info, DOMAIN_CONTRIBUTION_AND_PROOF, Some(epoch));
    secure_sign(pk_hex, contribution_and_proof, domain)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#submit-deposit
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_deposit_signature(
    pk_hex: String,
    deposit_message: DepositMessage,
    fork_version: Version,
) -> Result<DepositResponse> {
    let domain = compute_domain(DOMAIN_DEPOSIT, Some(fork_version), None);
    let sig = secure_sign(pk_hex, deposit_message.clone(), domain)?;

    let dm_root = deposit_message.tree_hash_root().to_fixed_bytes();

    let dd = DepositData {
        pubkey: deposit_message.pubkey.clone(),
        withdrawal_credentials: deposit_message.withdrawal_credentials,
        amount: deposit_message.amount,
        signature: sig.clone(),
    };

    let dd_root = dd.tree_hash_root().to_fixed_bytes();

    let dr = DepositResponse {
        pubkey: hex::encode(&deposit_message.pubkey[..]),
        withdrawal_credentials: hex::encode(deposit_message.withdrawal_credentials),
        amount: deposit_message.amount,
        signature: hex::encode(&sig[..]),
        deposit_message_root: hex::encode(dm_root),
        deposit_data_root: hex::encode(dd_root),
    };

    Ok(dr)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntary-exits
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_voluntary_exit_signature(
    pk_hex: String,
    fork_info: ForkInfo,
    voluntary_exit: VoluntaryExit,
) -> Result<BLSSignature> {
    let domain = get_domain(fork_info, DOMAIN_VOLUNTARY_EXIT, Some(voluntary_exit.epoch));
    secure_sign(pk_hex, voluntary_exit, domain)
}

/// https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#signing
/// Modified to adhere to https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn get_validator_registration_signature(
    pk_hex: String,
    validator_registration: ValidatorRegistration,
) -> Result<BLSSignature> {
    // altair - works with Lighthouse Web3Signer test...
    // let fork_version: Version = [128, 0, 0, 105];

    // works with mev-boost test...
    let fork_version: Version = [0_u8, 0_u8, 0_u8, 0_u8]; // 0x00000000

    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, Some(fork_version), None);
    secure_sign(pk_hex, validator_registration, domain)
}

// Define a new trait
pub trait Signable {
    fn to_signing_root(&self) -> Root
    where
        Self: Sized;
}

impl Signable for BLSSignMsg {
    fn to_signing_root(&self) -> Root {
        self.to_signing_root()
    }
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

impl BLSSignMsg {
    pub fn can_be_slashed(&self) -> bool {
        if let BLSSignMsg::BLOCK(_)
        | BLSSignMsg::block(_)
        | BLSSignMsg::BLOCK_V2(_)
        | BLSSignMsg::block_v2(_)
        | BLSSignMsg::ATTESTATION(_)
        | BLSSignMsg::attestation(_) = self
        {
            true
        } else {
            false
        }
    }

    pub fn to_signing_root(&self) -> Root {
        match self {
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
            BLSSignMsg::BLOCK(m) | BLSSignMsg::block(m) => {
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_BEACON_PROPOSER,
                    Some(compute_epoch_at_slot(m.block.slot.clone())),
                );
                compute_signing_root(m.block.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#signature
            BLSSignMsg::BLOCK_V2(m) | BLSSignMsg::block_v2(m) => {
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_BEACON_PROPOSER,
                    Some(compute_epoch_at_slot(
                        m.beacon_block.block_header.slot.clone(),
                    )),
                );
                compute_signing_root(m.beacon_block.block_header.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#attesting
            BLSSignMsg::ATTESTATION(m) | BLSSignMsg::attestation(m) => {
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_BEACON_ATTESTER,
                    Some(m.attestation.target.epoch.clone()),
                );

                compute_signing_root(m.attestation.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#randao-reveal
            BLSSignMsg::RANDAO_REVEAL(m) | BLSSignMsg::randao_reveal(m) => {
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_RANDAO,
                    Some(m.randao_reveal.epoch),
                );
                compute_signing_root(m.randao_reveal.epoch, domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#broadcast-aggregate
            BLSSignMsg::AGGREGATE_AND_PROOF(m) | BLSSignMsg::aggregate_and_proof(m) => {
                let epoch =
                    compute_epoch_at_slot(m.aggregate_and_proof.aggregate.data.slot.clone());
                let domain =
                    get_domain(m.fork_info.clone(), DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
                compute_signing_root(m.aggregate_and_proof.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection
            BLSSignMsg::AGGREGATION_SLOT(m) | BLSSignMsg::aggregation_slot(m) => {
                let epoch = compute_epoch_at_slot(m.aggregation_slot.slot.clone());
                let domain = get_domain(m.fork_info.clone(), DOMAIN_SELECTION_PROOF, Some(epoch));
                compute_signing_root(m.aggregation_slot.slot.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#submit-deposit
            BLSSignMsg::DEPOSIT(m) | BLSSignMsg::deposit(m) => {
                let domain =
                    compute_domain(DOMAIN_DEPOSIT, Some(m.genesis_fork_version.clone()), None);
                compute_signing_root(m.deposit.clone(), domain)
            }
            /// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntary-exits
            BLSSignMsg::VOLUNTARY_EXIT(m) | BLSSignMsg::voluntary_exit(m) => {
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_VOLUNTARY_EXIT,
                    Some(m.voluntary_exit.epoch.clone()),
                );
                compute_signing_root(m.voluntary_exit.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee-messages
            BLSSignMsg::SYNC_COMMITTEE_MESSAGE(m) | BLSSignMsg::sync_committee_message(m) => {
                let epoch = compute_epoch_at_slot(m.sync_committee_message.slot.clone());
                let domain = get_domain(m.fork_info.clone(), DOMAIN_SYNC_COMMITTEE, Some(epoch));
                compute_signing_root(m.sync_committee_message.beacon_block_root, domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection
            BLSSignMsg::SYNC_COMMITTEE_SELECTION_PROOF(m)
            | BLSSignMsg::sync_committee_selection_proof(m) => {
                let epoch = compute_epoch_at_slot(m.sync_aggregator_selection_data.slot.clone());
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                    Some(epoch),
                );
                compute_signing_root(m.sync_aggregator_selection_data.clone(), domain)
            }
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution
            BLSSignMsg::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF(m)
            | BLSSignMsg::sync_committee_contribution_and_proof(m) => {
                let epoch =
                    compute_epoch_at_slot(m.contribution_and_proof.contribution.slot.clone());
                let domain = get_domain(
                    m.fork_info.clone(),
                    DOMAIN_CONTRIBUTION_AND_PROOF,
                    Some(epoch),
                );
                compute_signing_root(m.contribution_and_proof.clone(), domain)
            }
            // https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#signing
            BLSSignMsg::VALIDATOR_REGISTRATION(m) | BLSSignMsg::validator_registration(m) => {
                // works with mev-boost test...
                let fork_version: Version = [0_u8, 0_u8, 0_u8, 0_u8]; // 0x00000000
                let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, Some(fork_version), None);
                compute_signing_root(m.validator_registration.clone(), domain)
            }
            // TODO
            _ => Root::default(),
        }
    }
}

#[cfg(test)]
mod spec_tests {}

// #[cfg(test)]
// pub mod slash_resistance_tests {

//     use ssz_types::FixedVector;

//     use crate::key_management_old::new_keystore;
//     use crate::key_management_old;

//     use crate::slash_protection::SlashingProtectionData;
//     use super::*;
//     use std::fs;
//     use std::path::Path;

//     /// hardcoded bls sk from Lighthouse Web3Signer tests
//     pub fn setup_keypair() -> String {
//         // dummy key
//         let sk_hex = hex::encode(&[85, 40, 245, 17, 84, 193, 234, 155, 24, 234, 181, 58, 171, 193, 209, 164, 120, 147, 10, 174, 189, 228, 119, 48, 181, 19, 117, 223, 2, 240, 7, 108,]);
//         println!("DEBUG: using sk: {sk_hex}");

//         let sk = key_management_old::bls_sk_from_hex(sk_hex.clone()).unwrap();
//         let pk = sk.sk_to_pk();
//         let pk_hex = hex::encode(pk.compress());
//         // save keystore
//         let name = new_keystore(Path::new("./etc/keys/bls_keys/generated/"), "", &pk_hex, &sk.serialize()).unwrap();
//         println!("DEBUG: using pk: {pk_hex}");

//         // init slashing protection db
//         let db = SlashingProtectionData::from_pk_hex(pk_hex.clone()).unwrap();
//         db.write().unwrap();

//         pk_hex
//     }

//     /// hardcoded bls sk from mev-boost tests
//     /// https://github.com/flashbots/mev-boost/blob/33c9b946c940ef279fe2b8bf1492e913cc0b0c49/server/service_test.go#L165
//     pub fn setup_keypair2() -> String {
//         // dummy key
//         let sk_hex = "0x4e343a647c5a5c44d76c2c58b63f02cdf3a9a0ec40f102ebc26363b4b1b95033".to_string();

//         println!("DEBUG: using sk: {sk_hex}");

//         let sk = key_management_old::bls_sk_from_hex(sk_hex).unwrap();
//         let pk = sk.sk_to_pk();
//         let pk_hex = hex::encode(pk.compress());
//         // save keystore
//         let name = new_keystore(Path::new("./etc/keys/bls_keys/generated/"), "", &pk_hex, &sk.serialize()).unwrap();
//         println!("DEBUG: using pk: {pk_hex}");
//         // init slashing protection db
//         let db = SlashingProtectionData::from_pk_hex(pk_hex.clone()).unwrap();
//         db.write().unwrap();
//         pk_hex
//     }

//     #[test]
//     fn load_dummy_keys() {
//         setup_keypair();
//     }

//     pub fn mock_beacon_block(slot: &str) -> String {
//         let req = format!(r#"
//             {{
//                 "slot":"{slot}",
//                 "proposer_index":"5",
//                 "parent_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
//                 "state_root":"0x2b530d6262576277f1cc0dbe341fd919f9f8c5c92fc9140dff6db4ef34edea0d",
//                 "body":{{
//                     "randao_reveal":"0xa686652aed2617da83adebb8a0eceea24bb0d2ccec9cd691a902087f90db16aa5c7b03172a35e874e07e3b60c5b2435c0586b72b08dfe5aee0ed6e5a2922b956aa88ad0235b36dfaa4d2255dfeb7bed60578d982061a72c7549becab19b3c12f",
//                     "eth1_data":{{
//                     "deposit_root":"0x6a0f9d6cb0868daa22c365563bb113b05f7568ef9ee65fdfeb49a319eaf708cf",
//                     "deposit_count":"8",
//                     "block_hash":"0x4242424242424242424242424242424242424242424242424242424242424242"
//                     }},
//                     "graffiti":"0x74656b752f76302e31322e31302d6465762d6338316361363235000000000000",
//                     "proposer_slashings":[],
//                     "attester_slashings":[],
//                     "attestations":[],
//                     "deposits":[],
//                     "voluntary_exits":[]
//                 }}
//             }}"#);
//         req
//     }

//     fn send_n_proposals(n: u64) -> (String, Vec<BLSSignature>) {
//         // clear state
//         fs::remove_dir_all("./etc");

//         // new keypair
//         let bls_pk_hex = setup_keypair();

//         // make n requests
//         let sigs = (1..n+1).map(|s| {
//             let slot = format!("{s}");
//             let req = mock_beacon_block(&slot);
//             let b: BeaconBlock = serde_json::from_str(&req).unwrap();
//             let f = ForkInfo::default();
//             assert_eq!(b.slot, s);

//             let sig = get_block_signature(bls_pk_hex.clone(), f, b).unwrap();
//             println!("sig: {}", hex::encode(sig.to_vec()));
//             sig
//         }).collect();
//         (bls_pk_hex, sigs)
//     }

//     #[test]
//     fn test_propose_block_request() -> Result<()>{
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_proposals(n);
//         Ok(())
//     }

//     #[test]
//     #[should_panic]
//     fn test_propose_block_prevents_slash_when_decreasing_slot() {
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_proposals(n);

//         // make a request with slot < n and expect panic
//         let s = n - 1;
//         let slot = format!("{s}");

//         let req = mock_beacon_block(&slot);
//         let b: BeaconBlock = serde_json::from_str(&req).unwrap();
//         let f = ForkInfo::default();
//         assert_eq!(b.slot, s);

//         let sig = get_block_signature(bls_pk_hex.clone(), f, b).unwrap();
//         println!("sig: {}", hex::encode(sig.to_vec()));
//     }

//     #[test]
//     #[should_panic]
//     fn test_propose_block_prevents_slash_when_non_increasing_slot() {
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_proposals(n);

//         // make a request with slot = n and expect panic
//         let s = n;
//         let slot = format!("{s}");
//         let req = mock_beacon_block(&slot);
//         let b: BeaconBlock = serde_json::from_str(&req).unwrap();
//         let f = ForkInfo::default();
//         assert_eq!(b.slot, s);

//         let sig = get_block_signature(bls_pk_hex.clone(), f, b).unwrap();
//         println!("sig: {}", hex::encode(sig.to_vec()));
//     }

//     pub fn mock_attestation(src_epoch: &str, tgt_epoch: &str) -> String {
//         let req = format!(r#"
//         {{
//             "slot": "255",
//             "index": "65535",
//             "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
//             "source": {{
//                 "epoch": "{src_epoch}",
//                 "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
//             }},
//             "target": {{
//                 "epoch": "{tgt_epoch}",
//                 "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
//             }}
//         }}"#);
//         req
//     }

//     fn send_n_attestations(n: u64) -> (String, Vec<BLSSignature>) {
//         // clear state
//         fs::remove_dir_all("./etc");

//         // new keypair
//         let bls_pk_hex = setup_keypair();

//         // make n requests
//         let sigs = (1..n+1).map(|s| {
//             // source epoch will be non-decreasing
//             let src_epoch = format!("{s}");
//             // target epoch will be strictly increasing
//             let tgt_epoch = format!("{s}");
//             let req = mock_attestation(&src_epoch, &tgt_epoch);
//             let a: AttestationData = serde_json::from_str(&req).unwrap();
//             let f = ForkInfo::default();
//             assert_eq!(a.slot, 255);
//             assert_eq!(a.index, 65535);
//             assert_eq!(a.source.epoch, s);
//             assert_eq!(a.target.epoch, s);

//             let sig = get_attestation_signature(bls_pk_hex.clone(), f, a).unwrap();
//             println!("sig: {}", hex::encode(sig.to_vec()));
//             sig
//         }).collect();
//         (bls_pk_hex, sigs)
//     }

//     #[test]
//     fn test_attestation_request() -> Result<()>{
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_attestations(n);
//         Ok(())
//     }

//     #[test]
//     #[should_panic]
//     fn test_attestation_request_prevents_slash_when_decreasing_src_epoch(){
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_attestations(n);

//         // prev src epoch should be 50, but send 0
//         let src_epoch = "0";

//         // target epoch will be strictly increasing
//         let tgt_epoch = format!("{:x}", n + 1);

//         let req = mock_attestation(&src_epoch, &tgt_epoch);
//         let a: AttestationData = serde_json::from_str(&req).unwrap();
//         let f = ForkInfo::default();

//         let sig = get_attestation_signature(bls_pk_hex.clone(), f, a).unwrap();
//         println!("sig: {}", hex::encode(sig.to_vec()));
//     }

//     #[test]
//     #[should_panic]
//     fn test_attestation_request_prevents_slash_when_non_increasing_tgt_epoch(){
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_attestations(n);

//         // prev src epoch should be non-decreasing
//         let src_epoch = format!("{}", n + 1);
//         // target epoch will be equal (non-increasing)
//         let tgt_epoch = format!("{}", n);

//         let req = mock_attestation(&src_epoch, &tgt_epoch);
//         let a: AttestationData = serde_json::from_str(&req).unwrap();
//         assert_eq!(a.slot, 255);
//         assert_eq!(a.index, 65535);
//         assert_eq!(a.source.epoch, n+1);
//         assert_eq!(a.target.epoch, n);

//         let f = ForkInfo::default();
//         let sig = get_attestation_signature(bls_pk_hex.clone(), f, a).unwrap();
//         println!("sig: {}", hex::encode(sig.to_vec()));
//     }

//     #[test]
//     #[should_panic]
//     fn test_attestation_request_prevents_slash_when_decreasing_tgt_epoch(){
//         let n = 5;
//         let (bls_pk_hex, sigs) = send_n_attestations(n);

//         // prev src epoch should be non-decreasing
//         let src_epoch = format!("{:x}", n + 1);
//         // target epoch will be decreasing
//         let tgt_epoch = "0";

//         let req = mock_attestation(&src_epoch, &tgt_epoch);
//         let a: AttestationData = serde_json::from_str(&req).unwrap();
//         assert_eq!(a.slot, 255);
//         assert_eq!(a.index, 65535);
//         assert_eq!(a.source.epoch, n + 1);
//         assert_eq!(a.target.epoch, 0);

//         let f = ForkInfo::default();
//         let sig = get_attestation_signature(bls_pk_hex.clone(), f, a).unwrap();
//     }
// }