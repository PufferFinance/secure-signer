pub mod health;
pub mod secure_sign_bls;
pub mod list_bls_keys;
pub mod list_eth_keys;


#[derive(Clone)]
pub struct AppState {
    pub genesis_fork_version: crate::eth2::eth_types::Version,
    pub password_file: Option<String>
}

impl AppState {
    pub fn read_password(&self) -> Option<String> {
        // Check if a password file path is provided
        if let Some(password_file_path) = &self.password_file {
            let mut file = match std::fs::File::open(password_file_path) {
                Ok(file) => file,
                Err(_) => return None, // Return None if there was an error opening the file
            };

            let mut password = String::new();
            if let Err(_) = std::io::Read::read_to_string(&mut file, &mut password) {
                return None; // Return None if there was an error reading the file
            }

            Some(password)
        } else {
            None // Return None if no password file path is provided
        }
    }
}