use anyhow::bail;
use sha3::Digest;
pub mod handlers;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct KeygenWithBlockhashRequest {
    pub blockhash: String,
}

pub fn attest_new_eth_key_with_blockhash(
    blockhash: &str,
) -> anyhow::Result<(
    crate::io::remote_attestation::AttestationEvidence,
    ecies::PublicKey,
)> {
    // Generate a fresh SECP256K1 ETH keypair (saving ETH private key)
    let pk = crate::crypto::eth_keys::eth_key_gen()?;
    let blockhash: String = crate::strip_0x_prefix!(blockhash);
    let blockhash = hex::decode(blockhash)?;

    if blockhash.len() != 32 {
        bail!("Bad blockhash")
    }

    let mut hasher = sha3::Keccak256::new();
    hasher.update(&pk.serialize());
    let pk_hash = hasher.finalize();

    // Concatenate the two 32 Bytes
    let payload = ethers::abi::encode_packed(&[
        ethers::abi::Token::Bytes(pk_hash.to_vec()),
        ethers::abi::Token::Bytes(blockhash),
    ])?;

    // Commit to the payload
    let proof = crate::io::remote_attestation::AttestationEvidence::new(&payload)?;
    Ok((proof, pk))
}
