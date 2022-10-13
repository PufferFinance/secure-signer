
use anyhow::{Result, Context, bail};
use rand::AsByteSliceMut;
use serde_derive::{Deserialize, Serialize};
use ecies::PublicKey as EthPublicKey;

use std::ffi::CString;
use std::fmt;


use crate::keys;
// use super::do_epid_ra;

// Use this func sig for local development
use std::os::raw::c_char;
pub fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char) {}

#[derive(Serialize, Deserialize, Debug, Default)]
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

    /// Verifies attestation evidence IAS signatures
    pub fn verify_signature(&self) -> Result<()> {
        unimplemented!()
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


#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AttestationReport {
    pub id: String,
    pub timestamp: String,
    pub version: u32,
    pub epidPseudonym: String,
    pub advisoryURL: String,
    pub advisoryIDs: Vec<String>,
    pub isvEnclaveQuoteStatus: String,
    pub isvEnclaveQuoteBody: String,
}

#[derive(Debug)]
pub struct QuoteBody {
    pub VERSION        : u16,
    pub SIGNATURE_TYPE : u16,
    pub GID            : u32,
    pub ISVSVN_QE      : u16,
    pub ISVSVN_PCE     : u16,
    pub BASENAME       : Vec<u8>,
    pub CPUSVN         : Vec<u8>,
    pub MISCSELECT     : u32,
    pub ATTRIBUTES     : Vec<u8>,
    pub MRENCLAVE      : String,
    pub MRSIGNER       : String,
    pub ISVPRODID      : u16,
    pub ISVSVN         : u16,
    pub REPORTDATA     : Vec<u8>,
}

impl AttestationReport {
    /// Follows the API to decode https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    pub fn deserialize_quote_body(&self) -> Result<QuoteBody> {
        let body = &self.isvEnclaveQuoteBody;
        let body_decoded = base64::decode(body)?;

        if body_decoded.len() != 432 {
            bail!("base64 decoded quote body was not the right length of 432B!")
        }

        Ok(QuoteBody {
            VERSION:        u16::from_le_bytes(body_decoded[0..2].try_into()?),
            SIGNATURE_TYPE: u16::from_le_bytes(body_decoded[2..4].try_into()?) & 1,
            GID:            u32::from_le_bytes(body_decoded[4..8].try_into()?),
            ISVSVN_QE:      u16::from_le_bytes(body_decoded[8..10].try_into()?),
            ISVSVN_PCE:     u16::from_le_bytes(body_decoded[10..12].try_into()?),
                                         // RESERVED bytes [12..16]
            BASENAME:                          body_decoded[16..48].to_vec(),
            CPUSVN:                            body_decoded[48..64].to_vec(),
            MISCSELECT:     u32::from_le_bytes(body_decoded[64..68].try_into()?),
                                         // RESERVED bytes [68..96]
            ATTRIBUTES:                        body_decoded[96..112].to_vec(),
            MRENCLAVE:      hex::encode(&body_decoded[112..144]),
            MRSIGNER:       hex::encode(&body_decoded[176..208]),
                                         // RESERVED bytes [208..304]
            ISVPRODID:      u16::from_le_bytes(body_decoded[304..306].try_into()?),
            ISVSVN:         u16::from_le_bytes(body_decoded[306..308].try_into()?),
                                         // RESERVED bytes [308..368]
            REPORTDATA:                        body_decoded[368..432].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fetch_dummy_evidence() -> AttestationEvidence {
        let data = fs::read_to_string("./attestation_evidence.json").expect("Unable to read file");

        let evidence: AttestationEvidence = serde_json::from_slice(data.as_bytes()).unwrap();

        // println!("{:?}", evidence);
        evidence
    }

    #[test]
    fn test_deserialize_report() -> Result<()>{
        let evidence = fetch_dummy_evidence();
        
        println!("{:?}", evidence.raw_report);

        let report: AttestationReport = serde_json::from_slice(evidence.raw_report.as_bytes()).unwrap();

        println!("{:?}", report);

        let body = report.deserialize_quote_body()?;
        println!("{:?}", body);

        let pk_bytes = &body.REPORTDATA[0..33];

        // let pk = EthPublicKey::from(pk_bytes);
        let pk = EthPublicKey::parse_slice(pk_bytes, None)?;

        println!("recovered mrenclave from quote {:?}", body.MRENCLAVE);
        println!("recovered mrsigner from quote {:?}", body.MRSIGNER);
        println!("recovered pk from report data {:?}", pk);
        Ok(())
    }
}