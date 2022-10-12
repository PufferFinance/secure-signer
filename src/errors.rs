use reqwest;
use error_chain::error_chain;

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Reqwest(reqwest::Error);
        ParseIntError(std::num::ParseIntError);
    }
    errors { RandomResponseError(t: String) }
}