extern crate puffersecuresigner;
use puffersecuresigner::run;

#[tokio::main]
async fn main() {
    let port = std::env::args().nth(1).unwrap_or("3031".into()).parse::<u16>().expect("BAD PORT");
    println!("Starting SGX Secure-Aggregator: localhost:{}", port);
    run(port).await;
}