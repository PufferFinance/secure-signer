#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.secure_signer.health().await);
}

#[tokio::test]
async fn call_generate_eth_key_with_success() {
    let client = super::build_client();
    client.secure_signer.generate_eth_key().await.unwrap();
}

#[tokio::test]
async fn call_generate_bls_key_with_success() {
    let client = super::build_client();
    client.secure_signer.generate_bls_key().await.unwrap();
}

#[tokio::test]
async fn call_list_eth_keys_with_success() {
    let client = super::build_client();
    client.secure_signer.generate_eth_key().await.unwrap();
    assert!(
        client
            .secure_signer
            .list_eth_keys()
            .await
            .unwrap()
            .data
            .len()
            > 1
    );
}

#[tokio::test]
async fn call_list_bls_keys_with_success() {
    let client = super::build_client();
    client.secure_signer.generate_bls_key().await.unwrap();
    assert!(
        client
            .secure_signer
            .list_bls_keys()
            .await
            .unwrap()
            .data
            .len()
            > 1
    );
}
