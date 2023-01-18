use anyhow::{Result, Context, bail};
use blst::min_pk::PublicKey;
use openssl::stack::{Stack, StackRef};
use openssl::x509::{X509, X509StoreContext};
use openssl::x509::store::X509StoreBuilder;
use serde::Deserialize;
use serde_derive::{Serialize};
use ecies::PublicKey as EthPublicKey;

use std::ffi::CString;
use std::{fmt, fs};
use std::os::raw::c_char;


use crate::keys;

#[link(name = "epid")]
extern "C" {
   /// The cpp function for epid remote attestation with IAS defined in src/ra_wrapper.cpp
   fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char);
}

// Use this func sig for local development
// pub fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char) {}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AttestationEvidence {
    pub raw_report:    String,
    pub signed_report: String,
    pub signing_cert:  String,
}

impl AttestationEvidence {
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.len() > 64 {
            bail!("remote attestation report data exceed 64B limit!")
        }

        let mut sized_data: Vec<u8> = Vec::with_capacity(64);
        // add the data
        sized_data.extend_from_slice(data);
        // pad any remaining bytes with 0
        sized_data.extend_from_slice(&vec![0; 64 - data.len()]);

        let mut report_data = [0_u8; 64];
        report_data.clone_from_slice(&sized_data[..]);

        // sufficient sized buffers
        let a = [1_u8; 5000].to_vec();
        let b = [1_u8; 1000].to_vec();
        let c = [1_u8; 10000].to_vec();
        let report = CString::new(a).with_context(|| "CString::new failed")?;
        let signature = CString::new(b).with_context(|| "CString::new failed")?;
        let signing_cert = CString::new(c).with_context(|| "CString::new failed")?;

        // conv to pointer to pass into FFI
        let raw_rpt = report.into_raw();
        let raw_sig = signature.into_raw();
        let raw_cert = signing_cert.into_raw();

        // for scoping
        let mut rpt = CString::new("").with_context(|| "CString::new failed")?;
        let mut sig = CString::new("").with_context(|| "CString::new failed")?;
        let mut cert = CString::new("").with_context(|| "CString::new failed")?;

        unsafe {
            // call cpp EPID remote attestation lib
            do_epid_ra(&report_data as *const u8, raw_rpt, raw_sig, raw_cert);
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

    /// Verifies attestation evidence IAS signatures. During remote attestation
    /// IAS returns their signing certificate and root CA as concatenated PEMs.
    /// This function verifies that the signing certificate is rooted in Intel's root CA.
    pub fn verify_intel_signing_certificate(&self) -> Result<()> {
        // println!("{}", self.signing_cert);
        let x509s = X509::stack_from_pem(&self.signing_cert.as_bytes())?;

        // Extract intel's signing certificate
        let signing_x509 = match x509s.get(0) {
            Some(x) => x.to_owned(),
            None => bail!("Couldn't extract signing certificate pem!")
        };

        // Extract intel's root ca
        let root_x509 = match x509s.get(1) {
            Some(x) => x.to_owned(),
            None => bail!("Couldn't extract intel root CA pem!")
        };

        // Verify the common name is valid
        match signing_x509.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).into_iter().last() {
            Some(name) => {
                let n = name.data().as_utf8().with_context(|| "Couldn't convert x509 name data to string")?.to_string();
                if n != "Intel SGX Attestation Report Signing".to_string() {
                    bail!("The x509 certificate has an invalid common name: {}", n)
                }
            },
            None => bail!("Couldn't extract COMMONNAME from intel x509 cert")
        }

        // Verify the common name is valid
        match root_x509.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).into_iter().last() {
            Some(name) => {
                let n = name.data().as_utf8().with_context(|| "Couldn't convert x509 name data to string")?.to_string();
                if n != "Intel SGX Attestation Report Signing CA".to_string() {
                    bail!("The x509 certificate has an invalid common name: {}", n)
                }
            },
            None => bail!("Couldn't extract COMMONNAME from intel x509 cert")
        }

        let mut builder = X509StoreBuilder::new()?;
        let _ = builder.add_cert(root_x509.clone());
        let trust = builder.build();

        let mut cert_chain: Stack<X509> = Stack::new()?;
        cert_chain.push(root_x509).with_context(|| "could not push to cert chain")?;

        // Verify the signing_x509 is valid
        let mut store = X509StoreContext::new()?;
        match store.init(
            trust.as_ref(), 
            signing_x509.as_ref(), 
            cert_chain.as_ref(),
            |c| c.verify_cert()) {
                Ok(true) => Ok(()),
                _ => bail!("Failed to verify the intel signing certificate")
            }
    }

            
    pub fn get_bls_pk(&self) -> Result<PublicKey> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes()).with_context(|| "Couldn't get AttestationReport from AttestationEvidence.raw_report")?;
        let body = report.deserialize_quote_body()?;
        // println!("{:?}", body);
        let pk_bytes = &body.REPORTDATA[0..48];
        match PublicKey::deserialize(pk_bytes) {
            Ok(pk) => Ok(pk),
            Err(e) => bail!("bad pk_bytes embedded in attestation evidence, could not recover BLS public key: {:?}", e)
        }
    }

    pub fn get_eth_pk(&self) -> Result<EthPublicKey> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes()).with_context(|| "Couldn't get AttestationReport from AttestationEvidence.raw_report")?;
        let body = report.deserialize_quote_body()?;
        // println!("{:?}", body);
        let pk_bytes = &body.REPORTDATA[0..33];
        let pk = EthPublicKey::parse_slice(pk_bytes, None)?;
        Ok(pk)
    }

    pub fn get_mrenclave(&self) -> Result<String> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes()).with_context(|| "Couldn't get AttestationReport from AttestationEvidence.raw_report")?;
        let body = report.deserialize_quote_body()?;
        // println!("{:?}", body);
        Ok(body.MRENCLAVE)
    }


}

pub fn epid_remote_attestation(pk_hex: &String) -> Result<AttestationEvidence> {
    let pk_hex: String = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex).into();
    let len = pk_hex.len();
    let pk_bytes = match len {
        66 => { // Compressed SECP256K1 Key = 33B * 2 for hex = 66
            // Check the key exists
            println!("DEBUG: RA for ETH key {pk_hex}");
            let sk = keys::read_eth_key(&pk_hex)?;
            EthPublicKey::from_secret_key(&sk).serialize_compressed().to_vec()
        },
        96 => { // BLS public key = 48B * 2 for hex = 96
            println!("DEBUG: RA for BLS key {pk_hex}");
            // Check the key exists
            let sk = match keys::read_bls_key(&format!("generated/{pk_hex}")) {
                Ok(sk) => sk,
                Err(e) => keys::read_bls_key(&format!("imported/{pk_hex}"))?
            };
            sk.sk_to_pk().compress().to_vec()
        }
        _ => {
            // ERROR
            bail!(format!("RA for key {pk_hex}, bad length"))
        }

    };
    let proof = AttestationEvidence::new(&pk_bytes)?;
    println!("Got RA evidence {:?}", proof);
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
        let body_decoded = openssl::base64::decode_block(body)?;

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

pub fn fetch_dummy_evidence() -> AttestationEvidence {
    let data = fs::read_to_string("./attestation_evidence.json").expect("Unable to read file");

    let evidence: AttestationEvidence = serde_json::from_slice(data.as_bytes()).unwrap();

    // println!("{:?}", evidence);
    evidence
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_report() -> Result<()>{
        let evidence = fetch_dummy_evidence();
        
        println!("{:?}", evidence.raw_report);

        let report: AttestationReport = serde_json::from_slice(evidence.raw_report.as_bytes()).unwrap();

        println!("{:?}", report);

        let body = report.deserialize_quote_body()?;
        println!("{:?}", body);

        println!("recovered mrenclave from quote {:?}", body.MRENCLAVE);
        println!("recovered mrsigner from quote {:?}", body.MRSIGNER);
        Ok(())
    }

    #[test]
    fn test_get_eth_pk() -> Result<()>{
        let evidence = fetch_dummy_evidence();
        let pk = evidence.get_eth_pk()?;
        println!("recovered pk from report data {:?}", pk);
        Ok(())
    }

    #[test]
    fn test_verify_intel_signing_certificate() -> Result<()>{
        let evidence = fetch_dummy_evidence();

        evidence.verify_intel_signing_certificate()
    }


}