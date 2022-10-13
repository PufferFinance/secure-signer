
use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize, Serialize};
use ecies::PublicKey as EthPublicKey;

use std::ffi::CString;
use std::fmt;


use crate::keys;
// use super::do_epid_ra;

// Use this func sig for local development
use std::os::raw::c_char;
pub fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char) {}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationEvidence {
    pub raw_report:    String,
    pub signed_report: String,
    pub signing_cert:  String,
}

impl AttestationEvidence {
    /// TODO clean up expects with anyhow crate
    /// currently accepts a compressed pk (33B) as the data to commit to the report
    pub fn new(data: [u8; 33]) -> Result<Self> {

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
            do_epid_ra(&data as *const u8, raw_rpt, raw_sig, raw_cert);
            rpt = CString::from_raw(raw_rpt);
            sig = CString::from_raw(raw_sig);
            cert = CString::from_raw(raw_cert);
        }

        let raw_report  = String::from_utf8(rpt.to_bytes().to_vec()).expect("failed to conv to String");
        let signed_report  = String::from_utf8(sig.to_bytes().to_vec()).expect("failed to conv to String");
        let signing_cert = String::from_utf8(cert.to_bytes().to_vec()).expect("failed to conv to String");
        
        Ok(AttestationEvidence {
            raw_report,
            signed_report,
            signing_cert
        })
    }
}

pub fn epid_remote_attestation(pk_hex: &String) -> Result<AttestationEvidence> {
    let sk = keys::read_eth_key(pk_hex)?;
    let proof = AttestationEvidence::new(
        EthPublicKey::from_secret_key(&sk).serialize_compressed()
    )?;
    println!("{:?}", proof.signed_report);
    Ok(proof)
}
