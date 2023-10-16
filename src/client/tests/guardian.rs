use crate::enclave::types::KeyGenResponse;

#[tokio::test]
async fn call_health_with_success() {
    let client = super::build_client();
    assert!(client.guardian.health().await);
}

#[tokio::test]
async fn call_attest_fresh_eth_with_success() {
    let client = super::build_client();

    // This will panic if the call fails in any way
    let _resp: KeyGenResponse = client
        .guardian
        .attest_fresh_eth_key("0x0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .unwrap();

    dbg!(_resp);
}

#[tokio::test]
async fn call_attest_fresh_eth_with_failure_bad_blockhash() {
    let client = super::build_client();

    // This will panic if the call fails in any way
    assert!(client
        .guardian
        .attest_fresh_eth_key("0xdeadbeef") // Not 32B
        .await
        .is_err())
}
