pub mod handlers;
use anyhow::{Context, Result};

pub(crate) async fn attest_new_eth_key() -> Result<(
    crate::io::remote_attestation::AttestationEvidence,
    ecies::PublicKey,
)> {
    // Generate a fresh SECP256K1 ETH keypair (saving ETH private key)
    let pk = crate::crypto::eth_keys::eth_key_gen()?;

    // Sign the public key with CVM Agent session key
    let proof =
        crate::io::remote_attestation::AttestationEvidence::new(&pk.serialize_compressed()).await?;
    Ok((proof, pk))
}

pub(crate) async fn attest_new_bls_key() -> Result<(
    crate::io::remote_attestation::AttestationEvidence,
    blsttc::PublicKey,
)> {
    // Generate a fresh BLS keypair (saving BLS private key)
    let sk = crate::crypto::bls_keys::new_bls_key(0);
    let pk = sk.public_keys().public_key();
    crate::crypto::bls_keys::save_bls_key(&sk).with_context(|| "Failed to save BLS key")?;

    // Create a new slashing protection database
    crate::eth2::slash_protection::SlashingProtectionData::from_pk_hex(&pk.to_hex())?.write()?;

    // Sign the public key with CVM Agent session key
    let proof = crate::io::remote_attestation::AttestationEvidence::new(&pk.to_bytes()).await?;
    Ok((proof, pk))
}
