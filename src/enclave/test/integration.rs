use crate::eth2::eth_types::GENESIS_FORK_VERSION;

#[test]
fn guardian_receives_keyshard_from_validator_with_custody() {
    let eigen_pod_data = crate::enclave::EigenPodData {
        eigen_pod_manager_address: ethers::abi::Address::random(),
        eigen_pod_proxy_address: ethers::abi::Address::random(),
        eigen_pod_beacon_address: ethers::abi::Address::random(),
        beacon_proxy_bytecode: vec![1, 2, 3, 4, 5],
    };

    let (_evidence, guardian_enclave_public_key) =
        crate::api::eth_keygen_route::attest_new_eth_key_with_blockhash("").unwrap();

    let guardians = vec![guardian_enclave_public_key];

    let keygen_payload = crate::enclave::validator::handlers::attest_fresh_bls_key(
        bytes::Bytes::from(vec![0u8; 32]),
        eigen_pod_data.clone(),
        guardians,
        1,
        GENESIS_FORK_VERSION,
    )
    .unwrap();
    dbg!(&keygen_payload);

    let (signature, message, has_custody) =
        crate::enclave::guardian::validate_custody::generate_signature(
            keygen_payload,
            0,
            guardian_enclave_public_key,
            eigen_pod_data,
        )
        .unwrap();

    // Check if signature is valid
    assert_eq!(
        libsecp256k1::verify(&message, &signature, &guardian_enclave_public_key),
        true
    );
    assert_eq!(has_custody, true);
}