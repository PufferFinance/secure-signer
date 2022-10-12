#[macro_use]
extern crate error_chain;

mod keys;
mod datafeed;
mod attest;
mod errors;
pub use errors::*;

use datafeed::get_btc_price_feed;

fn run() {
    if let Err(error) = get_btc_price_feed() {
        match *error.kind() {
            ErrorKind::Io(_) => println!("Standard IO error: {:?}", error),
            ErrorKind::Reqwest(_) => println!("Reqwest error: {:?}", error),
            ErrorKind::ParseIntError(_) => println!("Standard parse int error: {:?}", error),
            ErrorKind::RandomResponseError(_) => println!("User defined error: {:?}", error),
            _ => println!("Other error: {:?}", error),
        }
    }
}

fn main() {
    run();
}