#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.validator.health().await);
}

#[tokio::test]
async fn call_attest_fresh_bls_key_with_success() {
    let client = crate::client::ClientBuilder::new().build();
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: vec![
            hex_to_pubkey("04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("0x04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("0x04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf")
        ],
        withdrawal_credentials: [0; 32],
        threshold: 3,
        do_remote_attestation: true,
    };
    client
        .validator
        .attest_fresh_bls_key(&payload)
        .await
        .unwrap();
}

fn hex_to_pubkey(key: &str) -> libsecp256k1::PublicKey {
    let hex_string: String = crate::strip_0x_prefix!(key);
    let bytes = hex::decode(&hex_string).unwrap();

    libsecp256k1::PublicKey::parse_slice(&bytes, None).unwrap()
}

#[tokio::test]
async fn call_attest_fresh_bls_key_and_decrypt() {
    let n: usize = 4;

    // Setup Guardians
    let mut g_pks: Vec<ecies::PublicKey> = Vec::new();
    let mut g_sks: Vec<ecies::SecretKey> = Vec::new();
    for _ in 0..n {
        let (sk, pk) = crate::crypto::eth_keys::new_eth_key().unwrap();
        dbg!(hex::encode(sk.serialize()));
        dbg!(hex::encode(pk.serialize()));
        g_pks.push(pk);
        g_sks.push(sk);
    }

    let client = crate::client::ClientBuilder::new().build();
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: g_pks,
        withdrawal_credentials: [1; 32],
        threshold: 3,
        do_remote_attestation: true,
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

    assert!(false);
}
