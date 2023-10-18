use anyhow::{bail, Context, Result};
use blsttc::PublicKey;
use ecies::PublicKey as EthPublicKey;
use log::{debug, info};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};
use serde::Deserialize;
use serde_derive::Serialize;

use std::ffi::CString;
use std::os::raw::c_char;

#[cfg(feature = "sgx")]
#[link(name = "epid")]
extern "C" {
    /// The cpp function for epid remote attestation with IAS defined in src/ra_wrapper.cpp
    fn do_epid_ra(
        data: *const u8,
        report: *mut c_char,
        signature: *mut c_char,
        signing_cert: *mut c_char,
    );
}

#[cfg(not(feature = "sgx"))]
// Use this func sig for local development
pub fn do_epid_ra(
    _data: *const u8,
    _report: *mut c_char,
    _signature: *mut c_char,
    _signing_cert: *mut c_char,
) {
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub raw_report: String,
    pub signed_report: String,
    pub signing_cert: String,
}

impl AttestationEvidence {
    pub fn new(data: &[u8]) -> Result<Self> {
        info!("Attempting Remote Attestation");
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
        //TODO: vec with capacity; Currently using vec with capacity leads to failure in attestation
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
        let mut _rpt = CString::new("").with_context(|| "CString::new failed")?;
        let mut _sig = CString::new("").with_context(|| "CString::new failed")?;
        let mut _cert = CString::new("").with_context(|| "CString::new failed")?;

        unsafe {
            // call cpp EPID remote attestation lib
            do_epid_ra(&report_data as *const u8, raw_rpt, raw_sig, raw_cert);
            _rpt = CString::from_raw(raw_rpt);
            _sig = CString::from_raw(raw_sig);
            _cert = CString::from_raw(raw_cert);
        }

        let raw_report =
            String::from_utf8(_rpt.to_bytes().to_vec()).expect("failed to conv to String");
        let signed_report =
            String::from_utf8(_sig.to_bytes().to_vec()).expect("failed to conv to String");
        let signing_cert =
            String::from_utf8(_cert.to_bytes().to_vec()).expect("failed to conv to String");

        Ok(AttestationEvidence {
            raw_report,
            signed_report,
            signing_cert,
        })
    }

    /// Verifies attestation evidence IAS signatures. During remote attestation
    /// IAS returns their signing certificate and root CA as concatenated PEMs.
    /// This function verifies that the signing certificate is rooted in Intel's root CA.
    pub fn verify_intel_signing_certificate(&self) -> Result<()> {
        debug!("Verifying certificate {}", self.signing_cert);
        let x509s = X509::stack_from_pem(&self.signing_cert.as_bytes())?;

        // Extract intel's signing certificate
        let signing_x509 = match x509s.get(0) {
            Some(x) => x.to_owned(),
            None => bail!("Couldn't extract signing certificate pem!"),
        };

        // Extract intel's root ca
        let root_x509 = match x509s.get(1) {
            Some(x) => x.to_owned(),
            None => bail!("Couldn't extract intel root CA pem!"),
        };

        // Verify the common name is valid
        match signing_x509
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .into_iter()
            .last()
        {
            Some(name) => {
                let n = name
                    .data()
                    .as_utf8()
                    .with_context(|| "Couldn't convert x509 name data to string")?
                    .to_string();
                if n != "Intel SGX Attestation Report Signing".to_string() {
                    bail!("The x509 certificate has an invalid common name: {}", n)
                }
            }
            None => bail!("Couldn't extract COMMONNAME from intel x509 cert"),
        }

        // Verify the common name is valid
        match root_x509
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .into_iter()
            .last()
        {
            Some(name) => {
                let n = name
                    .data()
                    .as_utf8()
                    .with_context(|| "Couldn't convert x509 name data to string")?
                    .to_string();
                if n != "Intel SGX Attestation Report Signing CA".to_string() {
                    bail!("The x509 certificate has an invalid common name: {}", n)
                }
            }
            None => bail!("Couldn't extract COMMONNAME from intel x509 cert"),
        }

        let mut builder = X509StoreBuilder::new()?;
        let _ = builder.add_cert(root_x509.clone());
        let trust = builder.build();

        let mut cert_chain: Stack<X509> = Stack::new()?;
        cert_chain
            .push(root_x509)
            .with_context(|| "could not push to cert chain")?;

        // Verify the signing_x509 is valid
        let mut store = X509StoreContext::new()?;
        match store.init(
            trust.as_ref(),
            signing_x509.as_ref(),
            cert_chain.as_ref(),
            |c| c.verify_cert(),
        ) {
            Ok(true) => Ok(()),
            _ => bail!("Failed to verify the intel signing certificate"),
        }
    }

    pub fn get_report_data(&self) -> Result<[u8; 64]> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes())
            .with_context(|| {
                "Couldn't get AttestationReport from AttestationEvidence.raw_report"
            })?;
        let body = report.deserialize_quote_body()?;
        let mut report_bytes: [u8; 64] = [0_u8; 64];
        report_bytes.clone_from_slice(&body.REPORTDATA[0..64]);
        Ok(report_bytes)
    }

    /// Expets the BLS public key to be in the first 48 bytes of report body
    pub fn get_bls_pk(&self) -> Result<PublicKey> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes())
            .with_context(|| {
                "Couldn't get AttestationReport from AttestationEvidence.raw_report"
            })?;
        let body = report.deserialize_quote_body()?;
        let mut pk_bytes: [u8; 48] = [0_u8; 48];
        pk_bytes.clone_from_slice(&body.REPORTDATA[0..48]);
        match  PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => Ok(pk),
            Err(e) => bail!("bad pk_bytes embedded in attestation evidence, could not recover BLS public key: {:?}", e)
        }
    }

    pub fn get_eth_pk(&self) -> Result<EthPublicKey> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes())
            .with_context(|| {
                "Couldn't get AttestationReport from AttestationEvidence.raw_report"
            })?;
        let body = report.deserialize_quote_body()?;
        let pk_bytes = &body.REPORTDATA[0..33];
        let pk = EthPublicKey::parse_slice(pk_bytes, None)?;
        Ok(pk)
    }

    pub fn get_mrenclave(&self) -> Result<String> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes())
            .with_context(|| {
                "Couldn't get AttestationReport from AttestationEvidence.raw_report"
            })?;
        let body = report.deserialize_quote_body()?;
        Ok(body.MRENCLAVE)
    }

    pub fn get_mrsigner(&self) -> Result<String> {
        let report: AttestationReport = serde_json::from_slice(self.raw_report.as_bytes())
            .with_context(|| {
                "Couldn't get AttestationReport from AttestationEvidence.raw_report"
            })?;
        let body = report.deserialize_quote_body()?;
        Ok(body.MRSIGNER)
    }
}

#[allow(non_snake_case)]
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

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct QuoteBody {
    pub VERSION: u16,
    pub SIGNATURE_TYPE: u16,
    pub GID: u32,
    pub ISVSVN_QE: u16,
    pub ISVSVN_PCE: u16,
    pub BASENAME: Vec<u8>,
    pub CPUSVN: Vec<u8>,
    pub MISCSELECT: u32,
    pub ATTRIBUTES: Vec<u8>,
    pub MRENCLAVE: String,
    pub MRSIGNER: String,
    pub ISVPRODID: u16,
    pub ISVSVN: u16,
    pub REPORTDATA: Vec<u8>,
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
            VERSION: u16::from_le_bytes(body_decoded[0..2].try_into()?),
            SIGNATURE_TYPE: u16::from_le_bytes(body_decoded[2..4].try_into()?) & 1,
            GID: u32::from_le_bytes(body_decoded[4..8].try_into()?),
            ISVSVN_QE: u16::from_le_bytes(body_decoded[8..10].try_into()?),
            ISVSVN_PCE: u16::from_le_bytes(body_decoded[10..12].try_into()?),
            // RESERVED bytes [12..16]
            BASENAME: body_decoded[16..48].to_vec(),
            CPUSVN: body_decoded[48..64].to_vec(),
            MISCSELECT: u32::from_le_bytes(body_decoded[64..68].try_into()?),
            // RESERVED bytes [68..96]
            ATTRIBUTES: body_decoded[96..112].to_vec(),
            MRENCLAVE: hex::encode(&body_decoded[112..144]),
            MRSIGNER: hex::encode(&body_decoded[176..208]),
            // RESERVED bytes [208..304]
            ISVPRODID: u16::from_le_bytes(body_decoded[304..306].try_into()?),
            ISVSVN: u16::from_le_bytes(body_decoded[306..308].try_into()?),
            // RESERVED bytes [308..368]
            REPORTDATA: body_decoded[368..432].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::eth_keys;

    fn fetch_dummy_bls_evidence() -> AttestationEvidence {
        let data: String = format!(
            r#"{{"raw_report":"{{\"id\":\"219966280568893600543427580608194089763\",\"timestamp\":\"2023-01-20T19:47:28.465440\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOKnQegP7jJKCRW0CuwocB1b9Ilk3LxdQfcm8RgfwktN7LzgWkmU1t7GzZf3P8g2cAAAAAAAAAAAAAAAAAAAAA\"}}","signed_report":"bCtv7P9lbBwuRNuHJfBMsmj6ylOlZGtboWJpKJuqXon/MU0I1j+AjNUR7eLrtcQ9gf3lc0kHGXe37JO7+PWTRIGUY3MWHsYXlzbuFO484xtvJqbMiluUgD2zKYY//0qVph+GKpgJSedPDVjxtk11KcVeEd0kRh21Jp/ltHy4S1xUPsXkDHSP6TgVMSJ361Wj/xg8cgML6+E2M4rAbgtVGXqjvHMNRNxrOa4jnWKi9mpb+9Wzgv8SyJ5Mqk7IGtyYD6KKiD9fGqVjZXr0HNdzVqzfN1LAUxTPpxniPDSgIKrnGE2i3W6fuc4CZYz9nDi2Pr9vNk8w857uewp+voIhxw==","signing_cert":"-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\nDaVzWh5aiEx+idkSGMnX\n-----END CERTIFICATE-----\n"}}"#
        );
        let evidence: AttestationEvidence = serde_json::from_slice(data.as_bytes()).unwrap();
        evidence
    }

    fn fetch_dummy_eth_evidence() -> AttestationEvidence {
        let data: String = format!(
            r#"{{"raw_report":"{{\"id\":\"160570024488614035835007146146534298031\",\"timestamp\":\"2023-01-20T19:50:20.677152\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAfAAAAAAAAAE2yt+DKX+yq83lz+hnlXoyXOtEe0PZj7lECfkmRha1yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfKVqa0/gzWpjVQg3i322z6vck7HlCZxB1j4Vwz1AqO0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}","signed_report":"Pf9N8fiHJLOK49W52a326RbMTkQPjb4+Xf2K74wJqrkbQEq/h2DUW3ESc3BxoxeyXBS3K/U2Dzy3yUvM5jbPdqjhPvT22WOGCmVbJwIERWioTq410gcBB0z3cMvUfJzSTa3lYnk+F41PSTZYRMBtUPdUXu9ptv0K8SYSHvw9nJ07JS46ihrPf238fugzRIJPsFNcnRWul05RGzTnRme0PaLMWXMoFEnLhAvCl6El2Xu9rtTuKwjLoacHeXtkABUcf/iKlCqDQDb/0a72b6OPx0u7iI5BBVdriGtci793oE+QVOxPZejpUOmNRXd+5RUUO9yvwP2oqbPIJ5IIv5GLQw==","signing_cert":"-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\nDaVzWh5aiEx+idkSGMnX\n-----END CERTIFICATE-----\n"}}"#
        );
        let evidence: AttestationEvidence = serde_json::from_slice(data.as_bytes()).unwrap();
        evidence
    }

    #[test]
    fn test_verify_bls_report() -> Result<()> {
        let exp_mre: String =
            "4db2b7e0ca5fecaaf37973fa19e55e8c973ad11ed0f663ee51027e499185ad72".into();
        let exp_mrs: String =
            "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e".into();
        let exp_bls_pk: String = "8e2a741e80fee324a0915b40aec28701d5bf48964dcbc5d41f726f1181fc24b4decbce05a4994d6dec6cd97f73fc8367".into();

        let evidence = fetch_dummy_bls_evidence();
        evidence.verify_intel_signing_certificate().unwrap();
        let report: AttestationReport =
            serde_json::from_slice(evidence.raw_report.as_bytes()).unwrap();
        let _body = report.deserialize_quote_body()?;
        assert_eq!(exp_mre, evidence.get_mrenclave()?);
        assert_eq!(exp_mrs, evidence.get_mrsigner()?);
        let got_pk = evidence.get_bls_pk()?.to_hex();
        assert_eq!(exp_bls_pk, got_pk);
        Ok(())
    }

    #[test]
    fn test_verify_eth_report() -> Result<()> {
        let exp_mre: String =
            "4db2b7e0ca5fecaaf37973fa19e55e8c973ad11ed0f663ee51027e499185ad72".into();
        let exp_mrs: String =
            "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e".into();
        let exp_eth_pk: String =
            "027ca56a6b4fe0cd6a635508378b7db6cfabdc93b1e5099c41d63e15c33d40a8ed".into();

        let evidence = fetch_dummy_eth_evidence();
        evidence.verify_intel_signing_certificate().unwrap();
        let report: AttestationReport =
            serde_json::from_slice(evidence.raw_report.as_bytes()).unwrap();
        let _body = report.deserialize_quote_body()?;
        assert_eq!(exp_mre, evidence.get_mrenclave()?);
        assert_eq!(exp_mrs, evidence.get_mrsigner()?);
        let _got_pk = eth_keys::eth_pk_to_hex(&evidence.get_eth_pk()?);
        let got_pk = hex::encode(evidence.get_eth_pk()?.serialize_compressed());
        assert_eq!(exp_eth_pk, got_pk);
        Ok(())
    }
}
