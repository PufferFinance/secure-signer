#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.validator.health().await);
}

#[tokio::test]
async fn call_generate_bls_key_with_success() {
    let client = crate::client::ClientBuilder::new().build();
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        blockhash: "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563".to_string(),
        guardian_pubkeys: vec![
            hex_to_pubkey("04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("0x04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf"),
            hex_to_pubkey("0x04fad76420abd33cfd92f51f31c47fe678922e476281b21aa8a738bcd56e37a776f678c94592d6aefd17af48b508feb1f27e82da4c0c46a253830e4d8637b3fbaf")
        ],
        withdrawal_credentials: [0; 32],
        threshold: 3,
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
