#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    let method = crate::client::secure_signer::SecureSignerMethod::Health;
    assert_eq!(
        client.call(method).await.unwrap(),
        crate::client::secure_signer::SecureSignerResponse::Health(reqwest::StatusCode::OK)
    );
}

#[tokio::test]
async fn call_list_eth_keys_with_success() {
    let client = super::build_client();
    let method = crate::client::secure_signer::SecureSignerMethod::ListEthKeys;
    dbg!(client.call(method).await.unwrap());
}

#[tokio::test]
async fn call_list_bls_keys_with_success() {
    let client = super::build_client();
    let method = crate::client::secure_signer::SecureSignerMethod::ListBlsKeys;
    dbg!(client.call(method).await.unwrap());
}

#[tokio::test]
async fn call_generate_bls_key_with_success() {
    let client = super::build_client();
    let method = crate::client::secure_signer::SecureSignerMethod::GenerateEthKey;
    dbg!(client.call(method).await.unwrap());
}
