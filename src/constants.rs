pub const KEYS_DIR: &str = "./etc/keys/";
pub const BLS_KEYS_DIR: &str = "./etc/keys/bls_keys/";
pub const ETH_KEYS_DIR: &str = "./etc/keys/eth_keys/";

pub const BLS_PUB_KEY_BYTES: usize = 48;
pub const BLS_PRIV_KEY_BYTES: usize = 32;
pub const ETH_COMPRESSED_PK_BYTES: usize = 33;
pub const ETH_SIGNATURE_BYTES: usize = 64;

pub const ALLOW_GROWABLE_SLASH_PROTECTION_DB: bool = true;