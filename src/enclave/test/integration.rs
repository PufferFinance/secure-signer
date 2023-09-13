#[test]
fn guardian_receives_keyshard_from_validator_with_custody() {
    let eigen_pod_data = crate::enclave::EigenPodData {
        eigen_pod_manager_address: ethers::abi::Address::random(),
        eigen_pod_beacon_address: ethers::abi::Address::random(),
        beacon_proxy_bytecode: vec![1, 2, 3, 4, 5],
        puffer_pool_address: ethers::abi::Address::random(),
        eigen_pod_proxy_init_code: vec![1, 2, 3, 4, 5],
        pod_account_owners: vec![ethers::abi::Address::random()],
    };

    let (_evidence, guardian_enclave_public_key) =
        crate::api::eth_keygen_route::attest_new_eth_key_with_blockhash(
            "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
        )
        .unwrap();

    let guardians = vec![guardian_enclave_public_key];

    let keygen_payload = crate::enclave::validator::handlers::attest_fresh_bls_key(
        bytes::Bytes::from(vec![0u8; 32]),
        eigen_pod_data.clone(),
        guardians,
        1,
        crate::eth2::eth_types::GENESIS_FORK_VERSION,
    )
    .unwrap();

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
