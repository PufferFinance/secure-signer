// #[macro_use]
extern crate anyhow;
extern crate env_logger;
extern crate libc;

pub mod constants;
pub mod crypto;
pub mod enclave;
// TODO: Check lighthouse if we can replace
pub mod eth2;
pub mod io;

#[macro_export]
macro_rules! strip_0x_prefix {
    ($hex:expr) => {
        $hex.strip_prefix("0x").unwrap_or(&$hex).into()
    };
}
