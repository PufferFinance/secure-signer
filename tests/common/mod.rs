// use puffersecuresigner::api::aggregate_route::AggregateRequest;
use puffersecuresigner::crypto::bls_keys;
use puffersecuresigner::crypto::eth_keys;
use puffersecuresigner::eth2::eth_signing::BLSSignMsg;
use puffersecuresigner::eth2::slash_protection::SlashingProtectionData;
use puffersecuresigner::io::key_management;

use anyhow::{Result};
use blsttc::{PublicKeyShare, SecretKeySet, SecretKeyShare, SignatureShare, PublicKeySet};
use ecies::{PublicKey as EthPublicKey};
use puffersecuresigner::strip_0x_prefix;
use std::fs;

// use self::register_helper::register_new_pod;

mod eth_keygen_helper; 
mod bls_keygen_helper; 
mod signing_helper; 

/// Reads the `SECURE_SIGNER_PORT` environment variable.
/// If the return value is Some(port), it is expected that Secure-Aggregator is running on localhost:port
pub fn read_secure_signer_port() -> Option<u16> {
    std::env::set_var("SECURE_SIGNER_PORT", "9001"); // TODOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO undo after testing
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