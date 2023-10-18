use tracing::Level;
use tracing_subscriber::filter;

pub fn get_trace_filter() -> filter::Targets {
    let trace_filter = filter::Targets::new()
        .with_target("hyper", Level::ERROR)
        .with_target("reqwest", Level::ERROR)
        .with_target("rustls", Level::ERROR)
        .with_target("tower_http", Level::ERROR)
        .with_target("trie", Level::ERROR)
        .with_target("trust_dns_proto", Level::ERROR)
        .with_target("trust_dns_resolver", Level::ERROR)
        .with_target("sqlx", Level::ERROR)
        .with_default(Level::DEBUG);
    trace_filter
}
