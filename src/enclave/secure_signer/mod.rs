pub mod handlers;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use log::error;
use log::info;

fn attest_new_eth_key() -> Result<(
    crate::io::remote_attestation::AttestationEvidence,
    ecies::PublicKey,
)> {
    // Generate a fresh SECP256K1 ETH keypair (saving ETH private key)
    let pk = crate::crypto::eth_keys::eth_key_gen()?;

    // Commit to the payload
    let proof =
        crate::io::remote_attestation::AttestationEvidence::new(&pk.serialize_compressed())?;
    Ok((proof, pk))
}

fn attest_new_bls_key() -> Result<(
    crate::io::remote_attestation::AttestationEvidence,
    blsttc::PublicKey,
)> {
    // Generate a fresh BLS keypair (saving BLS private key)
    let sk = crate::crypto::bls_keys::new_bls_key(0);
    let pk = sk.public_keys().public_key();
    crate::crypto::bls_keys::save_bls_key(&sk).with_context(|| "Failed to save BLS key")?;

    // Create a new slashing protection database
    crate::eth2::slash_protection::SlashingProtectionData::from_pk_hex(&pk.to_hex())?.write()?;

    // Commit to the payload
    let proof = crate::io::remote_attestation::AttestationEvidence::new(&pk.to_bytes())?;
    Ok((proof, pk))
}

/// Returns true if signing_data is a block proposal or attestation and is slashable
fn is_slashable(
    bls_pk_hex: &String,
    signing_data: &crate::eth2::eth_signing::BLSSignMsg,
) -> Result<bool> {
    // The slashing DB must exist
    let db: crate::eth2::slash_protection::SlashingProtectionData =
        crate::eth2::slash_protection::SlashingProtectionData::read(bls_pk_hex.as_str())?;

    match signing_data {
        crate::eth2::eth_signing::BLSSignMsg::BLOCK(m)
        | crate::eth2::eth_signing::BLSSignMsg::block(m) => {
            Ok(db.is_slashable_block_slot(m.block.slot))
        }
        crate::eth2::eth_signing::BLSSignMsg::BLOCK_V2(m)
        | crate::eth2::eth_signing::BLSSignMsg::block_v2(m) => {
            Ok(db.is_slashable_block_slot(m.beacon_block.block_header.slot))
        }

        crate::eth2::eth_signing::BLSSignMsg::ATTESTATION(m)
        | crate::eth2::eth_signing::BLSSignMsg::attestation(m) => Ok(db
            .is_slashable_attestation_epochs(
                m.attestation.source.epoch,
                m.attestation.target.epoch,
            )),
        _ => {
            // Only block proposals and attestations are slashable
            Ok(false)
        }
    }
}

fn update_slash_protection_db(
    bls_pk_hex: &String,
    signing_data: &crate::eth2::eth_signing::BLSSignMsg,
) -> Result<()> {
    info!("update_slash_protection_db()");
    let mut db: crate::eth2::slash_protection::SlashingProtectionData =
        crate::eth2::slash_protection::SlashingProtectionData::read(bls_pk_hex.as_str())?;
    let signing_root = signing_data.to_signing_root(None);
    match signing_data {
        crate::eth2::eth_signing::BLSSignMsg::BLOCK(m)
        | crate::eth2::eth_signing::BLSSignMsg::block(m) => {
            let b = crate::eth2::slash_protection::SignedBlockSlot {
                slot: m.block.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        crate::eth2::eth_signing::BLSSignMsg::BLOCK_V2(m)
        | crate::eth2::eth_signing::BLSSignMsg::block_v2(m) => {
            let b = crate::eth2::slash_protection::SignedBlockSlot {
                slot: m.beacon_block.block_header.slot,
                signing_root: Some(signing_root),
            };
            db.new_block(b, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        crate::eth2::eth_signing::BLSSignMsg::ATTESTATION(m)
        | crate::eth2::eth_signing::BLSSignMsg::attestation(m) => {
            let a = crate::eth2::slash_protection::SignedAttestationEpochs {
                source_epoch: m.attestation.source.epoch,
                target_epoch: m.attestation.target.epoch,
                signing_root: Some(signing_root),
            };
            db.new_attestation(a, crate::constants::ALLOW_GROWABLE_SLASH_PROTECTION_DB)?;
            db.write()
        }
        _ => {
            // Only block proposals and attestations are slashable
            error!("Attempted to update slash protection db with non-slashable msg type");
            bail!("Should not update slash protection db for non blocks/attestations")
        }
    }
}
