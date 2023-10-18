use crate::enclave::types::KeyGenResponse;

#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.guardian.health().await);
}

#[tokio::test]
async fn call_attest_fresh_eth_with_success() {
    let client = super::build_client();

    // This will panic if the call fails in any way
    let _resp: KeyGenResponse = client
        .guardian
        .attest_fresh_eth_key("0x0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .unwrap();

    dbg!(_resp);
}

#[tokio::test]
async fn call_attest_fresh_eth_with_failure_bad_blockhash() {
    let client = super::build_client();

    // This will panic if the call fails in any way
    assert!(client
        .guardian
        .attest_fresh_eth_key("0xdeadbeef") // Not 32B
        .await
        .is_err())
}

#[tokio::test]
async fn call_validate_custody_with_success() {
    let n: usize = 8;

    // Setup Guardians
    let mut g_pks: Vec<ecies::PublicKey> = Vec::new();
    let mut g_sks: Vec<ecies::SecretKey> = Vec::new();
    for _ in 0..n {
        let (sk, pk) = crate::crypto::eth_keys::new_eth_key().unwrap();
        g_pks.push(pk);
        g_sks.push(sk);
    }

    // Setup BlsKeygenPayload
    let client = crate::client::ClientBuilder::new().build();
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: g_pks,
        withdrawal_credentials: [1; 32],
        threshold: 7,
        do_remote_attestation: false,
    };

    let resp: crate::enclave::types::BlsKeygenPayload = client
        .validator
        .attest_fresh_bls_key(&payload)
        .await
        .unwrap();

    dbg!(&resp);

    let pk_set: blsttc::PublicKeySet =
        blsttc::PublicKeySet::from_bytes(hex::decode(&resp.bls_pub_key_set).unwrap()).unwrap();

    for i in 0..n {
        let g_sk = g_sks[i].clone();
        let enc_sk_bytes = hex::decode(&resp.bls_enc_priv_key_shares[i]).unwrap();
        let sk_bytes = crate::crypto::eth_keys::envelope_decrypt(&g_sk, &enc_sk_bytes).unwrap();
        let sk_share =
            blsttc::SecretKeyShare::from_bytes(sk_bytes[..].try_into().unwrap()).unwrap();
        assert_eq!(
            hex::encode(pk_set.public_key_share(i).to_bytes()),
            hex::encode(sk_share.public_key_share().to_bytes()),
        );
    }
}
