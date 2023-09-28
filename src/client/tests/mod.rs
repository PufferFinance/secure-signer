mod guardian;
mod secure_signer;
mod validator;

fn build_client() -> super::Client {
    let builder = super::ClientBuilder::new();
    builder.build()
}
