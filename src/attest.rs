use warp::{Filter, http::Response};

use std::ffi::CString;
use std::fmt;
use anyhow::{Result, Context, bail};

use serde_json::{json};
use serde_derive::{Deserialize, Serialize};
use ecies::PublicKey as EthPublicKey;
use ecies::SecretKey as EthSecretKey;


use crate::keys;
// use super::do_epid_ra;

#[derive(Serialize, Debug)]
pub struct AttestationProof {
    pub raw_report:    String,
    pub signed_report: String,
    pub signing_cert:  String,
}

impl AttestationProof {
    pub fn new(data: [u8; 33]) -> AttestationProof {

        // sufficient sized buffers
        let a = [1_u8; 5000].to_vec();
        let b = [1_u8; 1000].to_vec();
        let c = [1_u8; 10000].to_vec();
        let report = CString::new(a).expect("CString::new failed");
        let signature = CString::new(b).expect("CString::new failed");
        let signing_cert = CString::new(c).expect("CString::new failed");

        // conv to pointer to pass into FFI
        let raw_rpt = report.into_raw();
        let raw_sig = signature.into_raw();
        let raw_cert = signing_cert.into_raw();

        // for scoping
        let mut rpt = CString::new("").expect("CString::new failed");
        let mut sig = CString::new("").expect("CString::new failed");
        let mut cert = CString::new("").expect("CString::new failed");

        unsafe {
            // call cpp EPID remote attestation lib
            // do_epid_ra(&data as *const u8, raw_rpt, raw_sig, raw_cert);
            rpt = CString::from_raw(raw_rpt);
            sig = CString::from_raw(raw_sig);
            cert = CString::from_raw(raw_cert);
        }

        let raw_report  = String::from_utf8(rpt.to_bytes().to_vec()).expect("failed to conv to String");
        let signed_report  = String::from_utf8(sig.to_bytes().to_vec()).expect("failed to conv to String");
        let signing_cert = String::from_utf8(cert.to_bytes().to_vec()).expect("failed to conv to String");
        
        AttestationProof {
            raw_report,
            signed_report,
            signing_cert
        }
    }

    pub fn as_json_string(&self) -> String {
        serde_json::to_string_pretty(&json!({
            "raw_report": self.raw_report.clone(),
            "signed_report":  self.signed_report.clone(),
            "signing_cert": self.signing_cert.clone(),
        })).expect("fail to turn reports into pretty json")//.to_string()
    }
}

impl fmt::Display for AttestationProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_json_string())
    }
}

pub fn epid_remote_attestation(pk_hex: &String) -> Result<()> {
    let sk = keys::read_eth_key(pk_hex)?;
    let proof = AttestationProof::new(
        EthPublicKey::from_secret_key(&sk).serialize_compressed()
    );
    println!("{:?}", proof.signed_report);
    // todo 
    unimplemented!()
}

/// TODO
pub fn epid_remote_attestation_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let hi = warp::path("world")
    .and(warp::path::param())
    .and(warp::header("user-agent"))
    .map(|param: String, agent: String| {
        format!("Hello {}, whose agent is {}", param, agent)
    });
    hi
}