use blsttc::SecretKeySet;
use puffersecuresigner::crypto::bls_keys;
use puffersecuresigner::eth2::slash_protection::SlashingProtectionData;
use puffersecuresigner::strip_0x_prefix;

pub mod bls_keygen_helper;
pub mod eth_keygen_helper;
pub mod eth_specs;
pub mod getter_routes_helper;
pub mod signing_helper;

/// Reads the `SECURE_SIGNER_PORT` environment variable.
/// If the return value is Some(port), it is expected that Secure-Aggregator is running on localhost:port
pub fn read_secure_signer_port() -> Option<u16> {
    let port = match std::env::var("SECURE_SIGNER_PORT") {
        Ok(port_str) => match port_str.parse::<u16>() {
            Ok(port) => Some(port),
            Err(_) => None,
        },
        Err(_) => None,
    };

    if port.is_some() {
        dbg!("Testing against remote Secure-Signer @ port {port}");
    } else {
        dbg!("Testing against local and mocked HTTP endpoints");
    }
    port
}

/// hardcoded bls sk from Lighthouse Web3Signer tests
pub fn setup_dummy_keypair() -> String {
    // dummy key
    let sk_hex = "5528f51154c1ea9b18eab53aabc1d1a478930aaebde47730b51375df02f0076c";
    dbg!(&sk_hex);
    let sk_hex: String = strip_0x_prefix!(sk_hex);
    let sk_bytes = hex::decode(sk_hex).unwrap();
    let sk_set = SecretKeySet::from_bytes(sk_bytes).unwrap();
    bls_keys::save_bls_key(&sk_set).unwrap();
    let pk_hex = sk_set.public_keys().public_key().to_hex();

    // init slashing protection db
    let db = SlashingProtectionData::from_pk_hex(&pk_hex).unwrap();
    db.write().unwrap();

    pk_hex
}
