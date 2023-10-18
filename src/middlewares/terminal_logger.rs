use std::time::{Duration, SystemTime};

use axum::{http::Request, middleware::Next, response::Response};

pub async fn terminal_logger<B>(request: Request<B>, next: Next<B>) -> Response {
    // do something with `request`...
    let method = request.method().clone();
    let uri = request.uri().clone();

    println!(
        "Request received
    method {}
    path {}",
        method, uri,
    );

    let response = next.run(request).await;

    let status = response.status();

    println!(
        "Response sent
    method {method}
    path {uri}
    status {status}
"
    );

    response
}
