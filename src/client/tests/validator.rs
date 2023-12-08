use crate::strip_0x_prefix;

use crate::client::traits::ValidatorClientTrait;

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
        fork_version: crate::eth2::eth_types::GENESIS_FORK_VERSION,
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
        fork_version: crate::eth2::eth_types::GENESIS_FORK_VERSION,
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
}

#[tokio::test]
async fn sign_voluntary_exit_message_with_success() {
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
        fork_version: crate::eth2::eth_types::GENESIS_FORK_VERSION,
        do_remote_attestation: true,
    };
    let resp = client
        .validator
        .attest_fresh_bls_key(&payload)
        .await
        .unwrap();

    let epoch = 0;
    let validator_index = 1559;
    let fork_info = crate::eth2::eth_types::ForkInfo::default();

    let vem = client
        .validator
        .sign_voluntary_exit_message(
            resp.bls_pub_key.clone(),
            epoch,
            validator_index,
            fork_info.clone(),
        )
        .await
        .unwrap();
    dbg!(&vem.signature);
    let stripped: String = strip_0x_prefix!(vem.signature);

    let sig =
        blsttc::Signature::from_bytes(hex::decode(&stripped).unwrap().to_vec().try_into().unwrap())
            .unwrap();

    let voluntary_exit = crate::eth2::eth_types::VoluntaryExit {
        epoch,
        validator_index,
    };

    let vem_req = crate::eth2::eth_types::VoluntaryExitRequest {
        fork_info,
        signingRoot: None,
        voluntary_exit,
    };

    let root = crate::eth2::eth_signing::BLSSignMsg::VOLUNTARY_EXIT(vem_req).to_signing_root(None);
    assert!(resp
        .public_key_set()
        .unwrap()
        .public_key()
        .verify(&sig, root));
}
