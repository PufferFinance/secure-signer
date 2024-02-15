mod guardian;
mod secure_signer;
mod validator;

use crate::client::traits::{GuardianClientTrait, ValidatorClientTrait};

use crate::eth2::eth_types::GENESIS_FORK_VERSION;

fn build_client() -> super::Client {
    let builder = super::ClientBuilder::new();
    builder
        .validator_url("http://localhost:9003".to_string())
        .guardian_url("http://localhost:9002".to_string())
        .build()
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

    // Guardian's keys increase
    let r: crate::enclave::types::ListKeysResponse = client.guardian.list_eth_keys().await.unwrap();
    assert!(dbg!(r.data).len() > 0);

    // Assume guardian called rotateGuardianKey()

    // Assume fetched from on-chain by validator:
    let guardian_pk = crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(&resp1.pk_hex).unwrap();

    // Validator generates fresh key and provisions to Guardian
    let payload = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: vec![guardian_pk.clone()],
        withdrawal_credentials: withdrawal_credentials.clone(),
        threshold: threshold,
        fork_version: GENESIS_FORK_VERSION,
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
        keygen_payload: resp2.clone(),
        guardian_enclave_public_key: guardian_pk,
        mrenclave,
        mrsigner,
        verify_remote_attestation,
        validator_index: 0
    };

    // Guardian validates they received custody
    let resp3: crate::enclave::types::ValidateCustodyResponse =
        client.guardian.validate_custody(req).await.unwrap();

    dbg!(&resp3);

    // Guardian signs VEMs
    let req = crate::enclave::types::SignExitRequest {
        bls_pub_key_set: resp2.bls_pub_key_set.clone(),
        guardian_index: 0,
        validator_index: 0,
        fork_info: crate::eth2::eth_types::ForkInfo::default(),
    };
    let resp4: crate::enclave::types::SignExitResponse =
        client.guardian.sign_exit(req).await.unwrap();

    dbg!(resp4);
}

#[tokio::test]
async fn test_cli_keygen_verified_by_guardians() {
    let client = build_client();
    let verify_remote_attestation = false;
    let withdrawal_credentials = [1; 32];
    let threshold = 1;
    let password = "password".to_string();

    // Guardian generates fresh key
    let resp1: crate::enclave::types::KeyGenResponse = client
        .guardian
        .attest_fresh_eth_key("0x0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .unwrap();

    dbg!(&resp1);

    // Assume fetched from on-chain by validator:
    let guardian_pk = crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(&resp1.pk_hex).unwrap();

    // Validator generates a local encrypted keystore and provisions to Guardian
    let bls_keygen_input = crate::enclave::types::AttestFreshBlsKeyPayload {
        guardian_pubkeys: vec![guardian_pk.clone()],
        withdrawal_credentials: withdrawal_credentials.clone(),
        threshold: threshold,
        fork_version: GENESIS_FORK_VERSION,
        do_remote_attestation: verify_remote_attestation,
    };
    let bls_keygen_payload = dbg!(crate::client::keygen::generate_bls_keystore_handler(
        bls_keygen_input,
        &password
    )
    .unwrap());

    // Assume validator is enqueued on-chain
    let req = crate::enclave::types::ValidateCustodyRequest {
        keygen_payload: bls_keygen_payload.clone(),
        guardian_enclave_public_key: guardian_pk,
        mrenclave: "".to_string(),
        mrsigner: "".to_string(),
        verify_remote_attestation,
        validator_index: 0
    };

    // Guardian validates they received custody
    let resp3: crate::enclave::types::ValidateCustodyResponse =
        client.guardian.validate_custody(req).await.unwrap();

    dbg!(&resp3);

    // Guardian signs VEMs
    let req = crate::enclave::types::SignExitRequest {
        bls_pub_key_set: bls_keygen_payload.bls_pub_key_set.clone(),
        guardian_index: 0,
        validator_index: 0,
        fork_info: crate::eth2::eth_types::ForkInfo::default(),
    };
    let _resp4: crate::enclave::types::SignExitResponse =
        client.guardian.sign_exit(req).await.unwrap();
}
