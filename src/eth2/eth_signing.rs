use super::eth_types::*;
use crate::crypto::bls_keys;

use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use tree_hash::TreeHash;

/// Return the signing root for the corresponding signing data.
pub fn compute_signing_root<T: Encode + TreeHash>(ssz_object: T, domain: Domain) -> Root {
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
    let fv = fork_version.unwrap_or(GENESIS_FORK_VERSION);
    // let gvr = genesis_validators_root.unwrap_or([0_u8; 32]);
    let gvr = genesis_validators_root.unwrap_or(Root::default());
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[allow(non_camel_case_types)]
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

    pub fn to_signing_root(&self, _genesis_fork_version: Option<Version>) -> Root {
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
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#voluntary-exits
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
            // https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#signing
            BLSSignMsg::VALIDATOR_REGISTRATION(m) | BLSSignMsg::validator_registration(m) => {
                let domain =
                    compute_domain(DOMAIN_APPLICATION_BUILDER, _genesis_fork_version, None);
                compute_signing_root(m.validator_registration.clone(), domain)
            }
        }
    }
}
