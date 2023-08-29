// #[macro_use]
extern crate anyhow;
extern crate env_logger;
extern crate libc;

pub mod api;
pub mod constants;
pub mod crypto;
pub mod eth2;
pub mod io;

use warp::Filter;
use warp::Reply;

#[macro_export]
macro_rules! strip_0x_prefix {
    ($hex:expr) => {
        $hex.strip_prefix("0x").unwrap_or(&$hex).into()
    };
}

pub async fn run<F>(port: u16, routes: F)
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: Reply,
{
    env_logger::init();
    // Start the server with the all_routes
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
}
