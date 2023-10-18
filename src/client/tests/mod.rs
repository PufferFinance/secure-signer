mod guardian;
mod secure_signer;
mod validator;

fn build_client() -> super::Client {
    let builder = super::ClientBuilder::new();
    builder.build()
}

#[tokio::test]
async fn registration_flow_succeeds() {
    // let verify_remote_attestation = true;
    let verify_remote_attestation = false;
    let withdrawal_credentials = [1; 32];
    let threshold = 1;
    let mrenclave = "dd446cbfa09114de39462cb59404306d63994a713d3b068c9f78796605f5b3dd".into();
    let mrsigner = "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e".into();

    let client = build_client();

    // Guardian generates fresh key
    let resp1: crate::enclave::types::KeyGenResponse = client
        .guardian
        .attest_fresh_eth_key("0x0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .unwrap();

    dbg!(&resp1);

    let guardian_pk = crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(&resp1.pk_hex).unwrap();

    // Validator generates fresh key and provisions to Guardian
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: vec![guardian_pk.clone()],
        withdrawal_credentials: withdrawal_credentials.clone(),
        threshold: threshold,
        do_remote_attestation: verify_remote_attestation,
    };

    let resp2: crate::enclave::types::BlsKeygenPayload = client
        .validator
        .attest_fresh_bls_key(&payload)
        .await
        .unwrap();

    dbg!(&resp2);

    // Guardian validates they received custody
    let resp3: crate::enclave::types::ValidateCustodyResponse = client
        .guardian
        .validate_custody(resp2, guardian_pk, mrenclave, mrsigner, verify_remote_attestation)
        .await
        .unwrap();

    dbg!(&resp3);

    assert!(false);
}
