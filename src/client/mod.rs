mod routes;


#[tokio::main]
async fn main() {
    println!("Starting Client");
    assert!(routes::is_alive(9001).await.is_ok());

    let resp = routes::bls_keygen(9001).await.unwrap();
    dbg!(resp.pk_hex);

    let resp = routes::list_bls_keys(9001).await.unwrap();
    dbg!(resp.data);

    let resp = routes::eth_keygen(9001).await.unwrap();
    dbg!(resp.pk_hex);

    let resp = routes::list_eth_keys(9001).await.unwrap();
    dbg!(resp.data);
    println!("Stopping Client");
}