use crate::constants::BLS_PUB_KEY_BYTES;
use crate::io::key_management::{read_bls_key, write_bls_key, read_bls_keystore, write_bls_keystore};
use crate::strip_0x_prefix;

use blsttc::{
    PublicKeySet, PublicKeyShare, SecretKeySet, SecretKeyShare, Signature, SignatureShare,
};

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

/// Sanitizes a BLS public key hex string, and errors out if malformed.
pub fn sanitize_bls_pk_hex(bls_pk_hex: &String) -> Result<String> {
    let bls_pk: String = strip_0x_prefix!(bls_pk_hex);
    // The length expected to be double since hex-encoded
    if bls_pk.len() != 2 * BLS_PUB_KEY_BYTES {
        bail!("Invalid bls_pk_hex length")
    }
    Ok(bls_pk)
}

/// Generate a new BLS secret key
pub fn new_bls_key(threshold: usize) -> SecretKeySet {
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::random(threshold, &mut rng);
    assert!(sk_set.threshold() == threshold);
    sk_set
}

/// Write the BLS secret key to a secure file using the hex encoded pk as filename
pub fn save_bls_key(sk_set: &SecretKeySet) -> Result<()> {
    // Hex-encode pk and sk
    let pk_hex = sk_set.public_keys().public_key().to_hex();
    let sk_hex = hex::encode(sk_set.to_bytes());

    // Save to file
    write_bls_key(&pk_hex, &sk_hex).with_context(|| "aggregate bls sk failed to save")
}

/// Write the BLS secret key to an encrypted using the hex encoded pk as filename
pub fn save_bls_keystore(sk_set: &SecretKeySet, password: &String) -> Result<String> {
    // Hex-encode pk 
    let pk_hex = sk_set.public_keys().public_key().to_hex();

    // Save keystore
    let uuid = write_bls_keystore(&pk_hex, &sk_set.secret_key().to_bytes(), &password.to_string()).with_context(|| "aggregate bls sk failed to save")?;
    Ok(uuid)
}

/// Read the BLS secret key from a secure file using the hex encoded pk as filename
pub fn fetch_bls_sk(pk_hex: &String) -> Result<SecretKeySet> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let sk_bytes = read_bls_key(pk_hex)?;
    match SecretKeySet::from_bytes(sk_bytes) {
        Ok(sk) => Ok(sk),
        Err(e) => bail!("Error deserializing bls sk bytes: {:?}", e),
    }
}

/// Read the BLS secret key from an encrypted keystore file using the hex encoded pk as filename
pub fn fetch_bls_sk_keystore(pk_hex: &String, password: &String) -> Result<SecretKeySet> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let sk_bytes = read_bls_keystore(&pk_hex.to_string(), password)?;
    match SecretKeySet::from_bytes(sk_bytes) {
        Ok(sk) => Ok(sk),
        Err(e) => bail!("Error deserializing bls sk bytes: {:?}", e),
    }
}

/// Returns BLS signature over `msg` using the supplied BLS secret key
pub fn bls_agg_sign(secret_key_set: &SecretKeySet, msg: &[u8]) -> Signature {
    secret_key_set.secret_key().sign(msg)
}

/// Performs BLS signature on `msg` using the BLS secret key looked up from memory
/// with pk_hex as the file name.
pub fn bls_agg_sign_from_saved_sk(pk_hex: &String, msg: &[u8]) -> Result<Signature> {
    // Fetch the secret key set from memory using the provided pk_hex
    let secret_key_set = fetch_bls_sk(pk_hex)?;

    // Verify the supplied pk_hex matches the derived
    if pk_hex != &secret_key_set.public_keys().public_key().to_hex() {
        bail!("Mismatch with input and derived pk");
    }

    // Sign the message using the fetched secret key set
    Ok(bls_agg_sign(&secret_key_set, msg))
}

/// Distributes `n` key shares from a given BLS `SecretKeySet`.
/// Returns a vector of tuples containing the `SecretKeyShare` and corresponding `PublicKeyShare` for each node.
///
/// # Arguments
///
/// * `sk_set` - The `SecretKeySet` from which to generate the key shares.
/// * `n` - The number of key shares to generate.
pub fn distribute_key_shares(
    sk_set: &SecretKeySet,
    n: usize,
) -> Vec<(SecretKeyShare, PublicKeyShare)> {
    let pk_set = sk_set.public_keys();

    (0..n)
        .map(|id| {
            // TODO randomize each id
            let sk_share = sk_set.secret_key_share(id);
            let pk_share = pk_set.public_key_share(id);
            (sk_share, pk_share)
        })
        .collect()
}

/// Aggregate BLS signature shares into a single signature.
///
/// This function takes a reference to a PublicKeySet and a vector of SignatureShares.
/// It first maps the SignatureShares into a BTreeMap with their corresponding indices,
/// and then combines the signatures using the PublicKeySet's `combine_signatures` method.
///
/// # Arguments
///
/// * `pk_set`: &PublicKeySet - A reference to the PublicKeySet associated with the secret key shares.
/// * `sig_shares`: &Vec<SignatureShare> - A vector of SignatureShares to be aggregated.
///
/// # Returns
///
/// * `Result<Signature>`: A Result containing the aggregated Signature if successful, or an error otherwise.
///
/// # Errors
///
/// This function returns an error if the `combine_signatures` method fails.
pub fn aggregate_signature_shares(
    pk_set: &PublicKeySet,
    sig_shares: &Vec<SignatureShare>,
) -> Result<Signature> {
    let sig_shares: BTreeMap<usize, SignatureShare> = (0..sig_shares.len())
        .map(|id| (id, sig_shares[id].clone()))
        .collect();

    let aggregated_signature = pk_set
        .combine_signatures(sig_shares)
        .with_context(|| "Failed to aggregate signature shares")?;

    Ok(aggregated_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::key_management::{bls_key_exists, delete_bls_key};
    #[test]
    fn test_new_bls_key() {
        // Test for different threshold values
        let thresholds = vec![1, 3, 5];

        for threshold in thresholds {
            let sk_set = new_bls_key(threshold);
            assert_eq!(sk_set.threshold(), threshold, "Threshold value mismatch");
        }
    }

    #[test]
    fn test_save_and_fetch_bls_key() {
        let threshold = 3;
        let sk_set = new_bls_key(threshold);
        let pk_hex = sk_set.public_keys().public_key().to_hex();

        // Test save_bls_key
        save_bls_key(&sk_set).expect("Failed to save BLS key");

        // Verify the file was created
        assert!(bls_key_exists(&pk_hex));

        // Test fetch_bls_sk
        let fetched_sk_set = fetch_bls_sk(&pk_hex).expect("Failed to fetch BLS key");

        // Verify the fetched key is the same as the original
        assert!(sk_set == fetched_sk_set,);

        // Delete the BLS key
        delete_bls_key(&pk_hex).unwrap();

        // Verify the file was deleted
        assert!(!bls_key_exists(&pk_hex));
    }

    #[test]
    fn test_save_and_fetch_bls_keystore() {
        let threshold = 3;
        let sk_set = new_bls_key(threshold);
        let pk_hex = sk_set.public_keys().public_key().to_hex();
        let password = "password".to_string();

        // Test save_bls_key
        save_bls_keystore(&sk_set, &password).unwrap();

        // Verify the file was created
        assert!(bls_key_exists(&pk_hex));

        // Test fetch_bls_sk
        let fetched_sk_set = fetch_bls_sk_keystore(&pk_hex, &password).expect("Failed to fetch BLS key");

        // Verify the fetched key is the same as the original
        assert!(sk_set.secret_key().to_hex() == fetched_sk_set.secret_key().to_hex());

        // Delete the BLS key
        delete_bls_key(&pk_hex).unwrap();

        // Verify the file was deleted
        assert!(!bls_key_exists(&pk_hex));
    }

    #[test]
    fn test_bls_agg_sign_from_saved_sk_success() {
        let threshold = 1;
        let secret_key_set = new_bls_key(threshold);
        let public_key_set = secret_key_set.public_keys();
        let msg = b"Hello, world!";

        let pk_hex = public_key_set.public_key().to_hex();
        save_bls_key(&secret_key_set).expect("Failed to save the secret key set");

        let signature =
            bls_agg_sign_from_saved_sk(&pk_hex, msg).expect("Failed to sign the message");

        assert!(
            public_key_set.public_key().verify(&signature, msg),
            "Signature verification failed"
        );
    }

    #[test]
    #[should_panic]
    fn test_bls_agg_sign_from_saved_sk_fails_if_not_saved() {
        let threshold = 1;
        let secret_key_set = new_bls_key(threshold);
        let public_key_set = secret_key_set.public_keys();
        let msg = b"Hello, world!";

        let pk_hex = public_key_set.public_key().to_hex();

        // Should fail
        bls_agg_sign_from_saved_sk(&pk_hex, msg).expect("Failed to sign the message");
    }

    #[test]
    fn test_distribute_key_shares() {
        let threshold = 2;
        let secret_key_set = new_bls_key(threshold);
        let n = 5;

        let key_shares = distribute_key_shares(&secret_key_set, n);

        assert_eq!(
            key_shares.len(),
            n,
            "Incorrect number of key shares generated"
        );

        let msg = b"Hello, world!";
        let _pk_set = secret_key_set.public_keys();

        // Sign the message with each secret key share
        let sig_shares: Vec<SignatureShare> = key_shares
            .iter()
            .map(|(sk_share, _)| sk_share.sign(msg))
            .collect();

        // Verify each signature share using the corresponding public key share
        for (i, (sig_share, (_, pk_share))) in sig_shares.iter().zip(key_shares.iter()).enumerate()
        {
            assert!(
                pk_share.verify(sig_share, msg),
                "Signature share verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_distribute_key_shares_and_aggregate_signature_shares() {
        let threshold = 2;
        let sk_set = new_bls_key(threshold);
        let n = 5;
        let key_shares = distribute_key_shares(&sk_set, n);
        let pk_set = sk_set.public_keys();

        let msg = b"Hello, world!";
        let sig_shares: Vec<SignatureShare> = key_shares
            .iter()
            .map(|(sk_share, _)| sk_share.sign(msg))
            .collect();

        // Aggregate the signatures
        let aggregated_signature = aggregate_signature_shares(&pk_set, &sig_shares).unwrap();

        // Verify the aggregated signature
        assert!(
            pk_set.public_key().verify(&aggregated_signature, msg),
            "Failed to verify aggregated signature"
        );
    }

    #[test]
    #[should_panic]
    fn test_aggregate_signature_shares_not_enough_shares() {
        let threshold = 3;
        let n = 5;
        let sk_set = new_bls_key(threshold);
        let pk_set = sk_set.public_keys();
        let msg = b"test message";
        let shares = distribute_key_shares(&sk_set, n);

        let sig_shares: Vec<SignatureShare> = shares
            .iter()
            .take(threshold) // Take one less than the threshold + 1
            .map(|(sk_share, _)| sk_share.sign(msg))
            .collect();

        aggregate_signature_shares(&pk_set, &sig_shares).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_aggregate_signature_shares_different_messages() {
        let threshold = 3;
        let n = 5;
        let sk_set = new_bls_key(threshold);
        let pk_set = sk_set.public_keys();
        let msg1 = b"test message 1";
        let msg2 = b"test message 2";
        let shares = distribute_key_shares(&sk_set, n);

        let mut sig_shares: Vec<SignatureShare> = Vec::new();
        for (i, (sk_share, _)) in shares.iter().enumerate().take(threshold) {
            let msg = if i == 0 { msg1 } else { msg2 };
            sig_shares.push(sk_share.sign(msg));
        }

        aggregate_signature_shares(&pk_set, &sig_shares).unwrap();
    }
}
