#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.guardian.health().await);
}

#[tokio::test]
async fn call_attest_fresh_eth_with_success() {
    let client = super::build_client();

    // This will panic if the call fails in any way
    client
        .guardian
        .attest_fresh_eth_key("0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
        .await
        .unwrap();
}
