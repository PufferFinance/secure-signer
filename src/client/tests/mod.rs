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
    let mrenclave = "758d532c6bd0a4297431623183e4d5dd5bbe274ebd8bdf9cecfcb8bffefaf186".into();
    let mrsigner = "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e".into();

    let client = build_client();

    // Guardian generates fresh key
    let resp1: crate::enclave::types::KeyGenResponse = client
        .guardian
        .attest_fresh_eth_key("0x0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .unwrap();

    dbg!(&resp1);

    // Assume guardian called rotateGuardianKey()

    // Assume fetched from on-chain by validator:
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

    // Assume validator is enqueued on-chain
    let req = crate::enclave::types::ValidateCustodyRequest {
        keygen_payload: resp2,
        guardian_enclave_public_key: guardian_pk,
        mrenclave,
        mrsigner,
        verify_remote_attestation,
    };

    // Guardian validates they received custody
    let resp3: crate::enclave::types::ValidateCustodyResponse =
        client.guardian.validate_custody(req).await.unwrap();

    dbg!(&resp3);

    assert!(false);
}
