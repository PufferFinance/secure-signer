use anyhow::{Result, Context, bail};
use warp::{Filter, http::Response, http::StatusCode};
use crate::datafeed::get_btc_price_feed;


/// Sample client route for getting a specific datafeed
pub fn btc_pricefeed_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("datafeed"))
        .and_then(get_btc_price_feed)
}



#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tesssst() {
        let filter = btc_pricefeed_route();

        let res = warp::test::request()
            .path("/portal/v1/datafeed")
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);
        println!{"{:?}", res.body()};
    }
}