pub const KEYS_DIR: &str = "./etc/keys/";
pub const BLS_KEYS_DIR: &str = "./etc/keys/bls_keys/";
pub const ETH_KEYS_DIR: &str = "./etc/keys/eth_keys/";
pub const SLASHING_PROTECTION_DIR: &str = "./etc/slashing/";

pub const BLS_SIG_BYTES: usize = 96;
pub const BLS_PUB_KEY_BYTES: usize = 48;
pub const BLS_PRIV_KEY_BYTES: usize = 32;
pub const ETH_COMPRESSED_PK_BYTES: usize = 33;
pub const ETH_UNCOMPRESSED_PK_BYTES: usize = 65;
pub const ETH_SIGNATURE_BYTES: usize = 64;

pub const ALLOW_GROWABLE_SLASH_PROTECTION_DB: bool = false;

pub const FULL_DEPOSIT_AMOUNT: u64 = 32000000000;
pub const WITHDRAWAL_CREDENTIALS_BYTES: usize = 32;
