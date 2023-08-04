use crate::constants::{BLS_KEYS_DIR, ETH_KEYS_DIR};
use crate::strip_0x_prefix;
use anyhow::{bail, Context, Result};

use std::fs;
use std::path::PathBuf;

// Writes the sk_hex string to the specified path
fn write_key(file_path: PathBuf, sk_hex: &str) -> Result<()> {
    if let Some(p) = file_path.parent() {
        fs::create_dir_all(p).with_context(|| "Failed to create keys dir")?
    };
    fs::write(&file_path, sk_hex).with_context(|| "failed to write sk")
}

/// Writes the hex-encoded ETH secret key to a file named from `fname`
pub fn write_eth_key(pk_hex: &String, sk_hex: &String) -> Result<()> {
    // Sanitize inputs
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let sk_hex: &str = strip_0x_prefix!(sk_hex);
    let file_path: PathBuf = [ETH_KEYS_DIR, pk_hex].iter().collect();
    write_key(file_path, sk_hex)
}

/// Writes the hex-encoded BLS secret key to a file named from `fname`
pub fn write_bls_key(pk_hex: &String, sk_hex: &String) -> Result<()> {
    // Sanitize inputs
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let sk_hex: &str = strip_0x_prefix!(sk_hex);
    let file_path: PathBuf = [BLS_KEYS_DIR, pk_hex].iter().collect();
    write_key(file_path, sk_hex)
}

/// Reads hex-encoded secret key from the specified path and returns the hex-decoded bytes
fn read_key(file_path: PathBuf) -> Result<Vec<u8>> {
    let sk_rec_bytes = fs::read(&file_path).with_context(|| "Unable to read secret key")?;
    hex::decode(sk_rec_bytes).with_context(|| "Unable to hex-decode secret key")
}

/// Reads hex-encoded ETH secret key from a file named from `pk_hex` and returns the bytes
pub fn read_eth_key(pk_hex: &str) -> Result<Vec<u8>> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [ETH_KEYS_DIR, pk_hex].iter().collect();
    read_key(file_path)
}

/// Reads hex-encoded BLS secret key from a file named from `pk_hex` and returns the bytes
pub fn read_bls_key(pk_hex: &str) -> Result<Vec<u8>> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [BLS_KEYS_DIR, pk_hex].iter().collect();
    read_key(file_path)
}

/// Deletes the secret key saved at the specified path
fn delete_key(file_path: PathBuf) -> Result<()> {
    fs::remove_file(&file_path)
        .with_context(|| format!("failed to delete key at: {:?}", file_path.as_os_str()))
}

/// Deletes the ETH secret key saved at the specified path
pub fn delete_eth_key(pk_hex: &str) -> Result<()> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [ETH_KEYS_DIR, pk_hex].iter().collect();
    delete_key(file_path)
}

/// Deletes the BLS secret key saved at the specified path
pub fn delete_bls_key(pk_hex: &str) -> Result<()> {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [BLS_KEYS_DIR, pk_hex].iter().collect();
    delete_key(file_path)
}

/// Return true if the key at the specified path exists
fn key_exists(file_path: &PathBuf) -> bool {
    file_path.exists()
}

/// Return true if the ETH key at the specified path exists
pub fn eth_key_exists(pk_hex: &str) -> bool {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [ETH_KEYS_DIR, pk_hex].iter().collect();
    key_exists(&file_path)
}

/// Return true if the BLS key at the specified path exists
pub fn bls_key_exists(pk_hex: &str) -> bool {
    let pk_hex: &str = strip_0x_prefix!(pk_hex);
    let file_path: PathBuf = [BLS_KEYS_DIR, pk_hex].iter().collect();
    key_exists(&file_path)
}

/// Return the file names in the specified directory
fn list_fnames(path_to_dir: &str) -> Result<Vec<String>> {
    let paths = fs::read_dir(path_to_dir).with_context(|| "No keys saved in dir")?;

    let mut keys: Vec<String> = Vec::new();
    for path in paths {
        // Get the paths to each file in this dir
        let p = match path.as_ref().err() {
            Some(e) => bail!("failed to find path: {}", e),
            _ => path.unwrap(),
        };

        // remove path prefix, to grab just the file name
        let fname = p.file_name();

        match fname.to_os_string().into_string() {
            Ok(s) => keys.push(s),
            Err(e) => bail!("Error, bad file name in list_keys(): {:?}", e),
        }
    }
    Ok(keys)
}

/// Returns the file names of each of the saved bls secret keys, where each fname
/// is assumed to be the compressed public key in hex without the `0x` prefix.
pub fn list_bls_keys() -> Result<Vec<String>> {
    list_fnames(BLS_KEYS_DIR)
}

/// Returns the file names of each of the saved eth secret keys, where each fname
/// is assumed to be the eth wallet address derived from the eth public key in hex without the `0x` prefix.
pub fn list_eth_keys() -> Result<Vec<String>> {
    list_fnames(ETH_KEYS_DIR)
}

#[cfg(test)]
mod test_key_management {
    use super::*;
    use crate::constants::KEYS_DIR;
    use std::path::Path;

    // Helper function to read the content of a file
    fn read_file(file_path: &Path) -> Result<String> {
        fs::read_to_string(file_path).with_context(|| "failed to read")
    }

    #[test]
    fn test_write_key() {
        let file_path: PathBuf = [KEYS_DIR, "test"].iter().collect();

        let sk_hex = "abcdef123456";

        write_key(file_path.clone(), sk_hex).unwrap();

        let written_content = read_file(&file_path).unwrap();
        assert_eq!(written_content, sk_hex);
        fs::remove_dir_all("./etc").ok();
    }

    #[test]
    fn test_write_eth_key() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex = "0x1234abcd";
        let sk_hex = "0xabcdef123456";

        write_eth_key(&pk_hex.to_string(), &sk_hex.to_string()).unwrap();

        let file_path: PathBuf = [ETH_KEYS_DIR, "1234abcd"].iter().collect();
        let written_content = read_file(&file_path).unwrap();
        assert_eq!(written_content, "abcdef123456");
        fs::remove_dir_all("./etc").ok();
    }

    #[test]
    fn test_write_bls_key() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex = "0x1234abcd";
        let sk_hex = "0xabcdef123456";

        write_bls_key(&pk_hex.to_string(), &sk_hex.to_string()).unwrap();

        let file_path: PathBuf = [BLS_KEYS_DIR, "1234abcd"].iter().collect();
        let written_content = read_file(&file_path).unwrap();
        assert_eq!(written_content, "abcdef123456");
        fs::remove_dir_all("./etc").ok();
    }

    #[test]
    fn test_write_read_delete_eth_key() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex = "0x1234abcd";
        let sk_hex = "0xabcdef123456";

        // Write the ETH key
        write_eth_key(&pk_hex.to_string(), &sk_hex.to_string()).unwrap();

        // Read the ETH key
        let sk_bytes = read_eth_key(pk_hex).unwrap();
        assert_eq!(sk_bytes, vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56]);

        // Delete the ETH key
        delete_eth_key(pk_hex).unwrap();

        // Check if the ETH key was deleted
        assert!(!eth_key_exists(pk_hex));
    }

    #[test]
    fn test_write_read_delete_bls_key() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex = "0x1234abcd";
        let sk_hex = "0xabcdef123456";

        // Write the BLS key
        write_bls_key(&pk_hex.to_string(), &sk_hex.to_string()).unwrap();

        // Read the BLS key
        let sk_bytes = read_bls_key(pk_hex).unwrap();
        assert_eq!(sk_bytes, vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56]);

        // Delete the BLS key
        delete_bls_key(pk_hex).unwrap();

        // Check if the BLS key was deleted
        assert!(!bls_key_exists(pk_hex));
    }

    #[test]
    fn test_list_eth_keys() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex1 = "0x1234abcd";
        let sk_hex1 = "0xabcdef123456";
        let pk_hex2 = "0x5678ef01";
        let sk_hex2 = "0xdeadbeef2468";

        // Write ETH keys
        write_eth_key(&pk_hex1.to_string(), &sk_hex1.to_string()).unwrap();
        write_eth_key(&pk_hex2.to_string(), &sk_hex2.to_string()).unwrap();

        // List ETH keys
        let eth_keys = list_eth_keys().unwrap();
        assert_eq!(eth_keys.len(), 2);
        assert!(eth_keys.contains(&pk_hex1[2..].to_string()));
        assert!(eth_keys.contains(&pk_hex2[2..].to_string()));

        // Clean up
        delete_eth_key(pk_hex1).unwrap();
        delete_eth_key(pk_hex2).unwrap();

        // Check if the ETH keys were deleted
        assert!(!eth_key_exists(pk_hex1));
        assert!(!eth_key_exists(pk_hex2));

        let bls_keys = list_eth_keys().unwrap();
        assert_eq!(bls_keys.len(), 0);
    }

    #[test]
    fn test_list_bls_keys() {
        fs::remove_dir_all("./etc").ok();
        let pk_hex1 = "0x1234abcd";
        let sk_hex1 = "0xabcdef123456";
        let pk_hex2 = "0x5678ef01";
        let sk_hex2 = "0xdeadbeef2468";

        // Write BLS keys
        write_bls_key(&pk_hex1.to_string(), &sk_hex1.to_string()).unwrap();
        write_bls_key(&pk_hex2.to_string(), &sk_hex2.to_string()).unwrap();

        // List BLS keys
        let bls_keys = list_bls_keys().unwrap();
        assert_eq!(bls_keys.len(), 2);
        assert!(bls_keys.contains(&pk_hex1[2..].to_string()));
        assert!(bls_keys.contains(&pk_hex2[2..].to_string()));

        // Clean up
        delete_bls_key(pk_hex1).unwrap();
        delete_bls_key(pk_hex2).unwrap();

        // Check if the BLS keys were deleted
        assert!(!bls_key_exists(pk_hex1));
        assert!(!bls_key_exists(pk_hex2));

        let bls_keys = list_bls_keys().unwrap();
        assert_eq!(bls_keys.len(), 0);
    }
}
