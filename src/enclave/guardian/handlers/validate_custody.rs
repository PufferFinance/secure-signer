use anyhow::{anyhow, bail, Result};
use axum::response::IntoResponse;
use axum::Json;
use blsttc::PublicKeySet;
use ecies::PublicKey as EthPublicKey;
use libsecp256k1::SecretKey as EthSecretKey;
use log::{error, info};
use sha3::Digest;
use ssz_types::FixedVector;
use tree_hash::TreeHash;

pub async fn handler(
    Json(req): Json<crate::enclave::types::ValidateCustodyRequest>,
) -> axum::response::Response {
    info!("validate_custody()");
    let crate::enclave::types::ValidateCustodyRequest {
        keygen_payload,
        guardian_enclave_public_key,
        withdrawal_credentials,
    } = req;

    match generate_guardian_signature(
        keygen_payload,
        guardian_enclave_public_key,
        withdrawal_credentials,
    ) {
        Ok(signature) => {
            let resp = crate::enclave::types::ValidateCustodyResponse { signature };
            (axum::http::status::StatusCode::OK, Json(resp)).into_response()
        }

        Err(e) => {
            error!("{:?}", e);
            (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}", e),
            )
                .into_response()
        }
    }
}

pub fn generate_guardian_signature(
    keygen_payload: crate::enclave::types::BlsKeygenPayload,
    guardian_enclave_pk: EthPublicKey,
    withdrawal_credentials: [u8; 32],
) -> Result<libsecp256k1::Signature> {
    // Read their enclave's eth secret key
    let Ok(guardian_enclave_sk) = crate::crypto::eth_keys::fetch_eth_key(
        &crate::crypto::eth_keys::eth_pk_to_hex(&guardian_enclave_pk),
    ) else {
        return Err(anyhow!("Could not fetch guardian enclave public key"));
    };

    // verify the remote attestation evidence

    // verify the deposit message is valid

    //

    // get the guardian's BLS secret key share
    let sk_share = verify_custody(guardian_enclave_sk, &keygen_payload)?;

    // save the keyshare
    // todo

    // return guardian enclave signature

    unimplemented!()

    // check_data_root(
    //     &validator_public_key_hex,
    //     withdrawal_credentials,
    //     &keygen_payload.signature,
    //     &keygen_payload.deposit_data_root,
    // )?;

    // # at this point we have verified:
    // # 1. if this enclave got custody of a private keyshare
    // # 2. the public keyshares is part of the aggregate
    // # 3. the validator submitted a valid signed deposit msg
    // # 4. the validator build a valid depositDataRoot

    // # sign final message
    // let (signature, _) = calculate_signature(
    //     &guardian_enclave_public_key,
    //     &validator_public_key_hex,
    //     &guardian_enclave_private_key,
    //     &withdrawal_credentials,
    //     keygen_payload.signature,
    //     keygen_payload.deposit_data_root,
    //     has_custody,
    // )?;

    // // We only need the signature
    // Ok(signature)
}

pub fn verify_remote_attestation_evidence(
    keygen_payload: crate::enclave::types::BlsKeygenPayload,
    mrenclave: &String,
) -> Result<bool> {
    let e = crate::io::remote_attestation::AttestationEvidence {
        raw_report: keygen_payload.intel_report,
        signed_report: keygen_payload.intel_sig,
        signing_cert: keygen_payload.intel_x509,
    };

    // Verify the evidence was signed from intel x509s
    e.verify_intel_signing_certificate()?;

    if &e.get_mrenclave()? != mrenclave {
        bail!("Invalid MRENCLAVE value");
    }

    let pk_set = PublicKeySet::from_bytes(hex::decode(&keygen_payload.bls_pub_key_set)?)?;

    let rec_payload = e.get_report_data()?;
    let mut dd_root: [u8; 32] = [0; 32];
    dd_root.copy_from_slice(&hex::decode(keygen_payload.deposit_data_root)?);
    let payload = crate::enclave::build_validator_remote_attestation_payload(
        pk_set,
        &hex::decode(keygen_payload.signature)?.into(),
        &dd_root,
        keygen_payload.bls_enc_priv_key_shares,
        keygen_payload
            .guardian_eth_pub_keys
            .iter()
            .map(|pk_hex| crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(pk_hex).unwrap())
            .collect(),
    )?;

    if hex::encode(rec_payload) != hex::encode(payload) {
        bail!("Invalid Remote Attestation commitments");
    }
    Ok(true)
}

fn check_data_root(
    validator_public_key_hex: &str,
    withdrawal_credentials_zero_padded: crate::eth2::eth_types::Bytes32,
    signature: &str,
    deposit_data_root: &ethers::types::TxHash,
) -> Result<()> {
    let signature: FixedVector<u8, _> = hex::decode(signature)?.into();
    let deposit_data = crate::eth2::eth_types::DepositData {
        pubkey: hex::decode(validator_public_key_hex.clone())?.into(),
        withdrawal_credentials: withdrawal_credentials_zero_padded,
        amount: 32,
        signature: signature.clone(),
    };

    if deposit_data.tree_hash_root().to_fixed_bytes() != deposit_data_root.to_fixed_bytes() {
        return Err(anyhow!("The deposit data root does not match"));
    };
    Ok(())
}

fn verify_custody(
    guardian_enclave_sk: EthSecretKey,
    keygen_payload: &crate::enclave::types::BlsKeygenPayload,
) -> Result<blsttc::SecretKeyShare> {
    let pk_set = PublicKeySet::from_bytes(hex::decode(&keygen_payload.bls_pub_key_set)?)?;
    let exp_pk_hex: String = crate::strip_0x_prefix!(keygen_payload.bls_pub_key);
    if pk_set.public_key().to_hex() != exp_pk_hex {
        bail!("Supplied bls_pub_key does not match dervied from bls_pub_key_set")
    }

    // Attempt to decrypt keyshares until a match is found
    for (i, enc_sk_hex) in keygen_payload.bls_enc_priv_key_shares.iter().enumerate() {
        dbg!(&enc_sk_hex);
        let enc_sk_bytes = hex::decode(&enc_sk_hex)?;
        let sk_bytes =
            crate::crypto::eth_keys::envelope_decrypt(&guardian_enclave_sk, &enc_sk_bytes);
        if sk_bytes.is_err() {
            continue;
        }

        // making it hear implies it is Ok()
        let sk_bytes = sk_bytes.unwrap();

        let sk_share = blsttc::SecretKeyShare::from_bytes(sk_bytes[..].try_into()?)?;

        dbg!(hex::encode(sk_share.to_bytes()));
        dbg!(hex::encode(sk_share.public_key_share().to_bytes()));

        // Check if a valid sk_share was decrypted
        if hex::encode(pk_set.public_key_share(i).to_bytes())
            == hex::encode(sk_share.public_key_share().to_bytes())
        {
            dbg!("match on iteration {:?}", i);
            dbg!(&sk_share);
            // save it
            return Ok(sk_share);
        }
    }

    bail!("custody check failed")
}

fn calculate_signature(
    guardian_enclave_public_key: &EthPublicKey,
    validator_public_key_hex: &str,
    guardian_enclave_private_key: &EthSecretKey,
    withdrawal_credentials: &crate::eth2::eth_types::Bytes32,
    signature: String,
    deposit_data_root: ethers::types::TxHash,
    has_custody: bool,
) -> Result<(libsecp256k1::Signature, libsecp256k1::Message)> {
    let signature: Vec<u8> = hex::decode(signature)?;

    let enclave_secret_key = crate::crypto::eth_keys::fetch_eth_key(
        &crate::crypto::eth_keys::eth_pk_to_hex(guardian_enclave_public_key),
    )?;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(hex::decode(validator_public_key_hex)?);
    hasher.update(guardian_enclave_private_key.serialize());
    hasher.update(withdrawal_credentials);
    hasher.update(signature.to_vec());
    hasher.update(deposit_data_root.as_bytes());
    hasher.update(vec![has_custody as u8]);
    let msg_to_be_signed = hasher.finalize();

    crate::crypto::eth_keys::sign_message(&msg_to_be_signed, &enclave_secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::types::BlsKeygenPayload;
    use ecies::{PublicKey as EthPublicKey, SecretKey as EthSecretKey};

    fn setup() -> (BlsKeygenPayload, Vec<EthSecretKey>, String, String) {
        let p = BlsKeygenPayload {
            bls_pub_key_set: "b927f246ed54236ce810f1296e9ee85574c4a59d7472aa50f9674d8ba8eb0d8b697065e22f86cad69f8526ee343fa4819390e8251a3b097db2d8916219069f38bb28f5c7371b84fbe3fbb9ed0e323fb3c5375f9efde1e139ad869e40621098b08f5bb3edce5981b4a238af666d1bda4dcccb0ab51f709db89f00358003315fabe55df8549e4d7a53d63a936789839664".to_owned(),
            bls_pub_key: "b927f246ed54236ce810f1296e9ee85574c4a59d7472aa50f9674d8ba8eb0d8b697065e22f86cad69f8526ee343fa481".to_owned(),
            signature: "8e5f46196fa45a0866bb1422d7283575683af565fe070d9af236a3cbf334b4ab0b5007400b5e6fb2fe86d2ed0f7206db14bc2f699483a9a2cf564db8201afeb374818e44182b000d2f97390a65599377a36da857381c3e7fb4fa1fd85786e1b9".to_owned(),
            deposit_data_root: "b28322d43f10b231f3631951f4fe444de646b8efee3647023068dd3d3db259ee".to_owned(),
            bls_enc_priv_key_shares: vec![
                "042d3af72fd7b32dbdbd7a84e0b31a8b676b5ca768c3a012c33addf88fb915885445efa027fa9678ad2ed3284750da8932ef365a0d431816109117cd423cc6bf05b0679d8ef171c1bff2275dbe0554ec65d7c75d0753d660173dd90f466e1cf5a773b6ffdb183b0d35cf79c6db0ea7017aa952a994a898e6776e71a337a7899efa".to_owned(),
                "0498dc487d2e039e5043d2fce25657fbb899b8aa96a8fad37929c580a688965991118650f32805f59b1ec3d4e4f07ee1472acfd5a2ee3bbed3f3240bfd18edfd7c863a0b07263830bf72a80ba219a0388e091185f06f73c668b5d0b24addc6665dfa2bb0c085a302f0ea2ec6d625ca8adcd5d8e0b16e51461809243d411fac5f4f".to_owned(),
                "04c1dc67b403f8da82954652ed312c0ee2bf310bd46b44c09ab92ad9c142afd98080cdbe7bb3935a9fae027fcec5b2f58b31511e089f1cebf5e7c02954f163f9224e33a8c38dc1ce5fd9187b0d4934280897168809ee652496c58f50f1ab47d6ac21eea0f5ebceff3fae7aad0e5d6ac853a4da6522141bcc2b2b328900170ca625".to_owned(),
                "04e7542fca87fb548a95fcdc5adbe27aafcd3778d2a500d2d199da3ea841745c515751a8ddd2bd50587d1c35c7db3625a6e807da06b8cf5a494f5cabaf43b64b42f21dfcdff4f4197328e00442842df22af07a3f9626ed5b868a05186f056ba80949993632185de389476be0cc6748437c03cf79a3df156cb90c911ba36f2a9fc1".to_owned(),
            ],
            intel_sig: "EgPYkFS0hsR21nkZp4+hLx6maoCh6exdwo56Qt0Y5mryMmJVEmf8hY1TugmGsAQXx8pI+awFojLcdXzeEeVt4/vT72kXTjjnk7fD7QJwVpUyjR+N1ZKU+As5z3qYef4/K6u4On1aED13EZkoV2i1HiJW1bNH591KbYdxf6/GoOYnM4zkk6HyjoR5rwcvImnQA/e6/B0psMx12h0fg9J5X27FjHM9Ny6hAf0ZVu/cAOt68Mx5zXaoZfpzsvqCX3GI1zVjTdS5DVHd0JAO2UPaSdb868fvTw/9TeYB7wW7GgSrXWvbXNdJ7O8pbGY4GzddxaGhIOnwx5+dkEESKyzndw==".to_owned(),
            intel_report: "{\"id\":\"160548001570880901939410887036502069906\",\"timestamp\":\"2023-10-18T02:29:20.020706\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhspNWPNBkpcmwf+3WZYsuncw6eX6Uijk+PzPp3dBQSebHsOEQYDRxGeFuWowvkTo2Z5HTavyoRIrSupBTqDE78HA=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAKwMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFRULB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAAKcssbqao4BqIt9gy8sWoJ26roquefickzkOsuvmE3zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNXyn9LrDxqGTMhsWQUXvDhFF9Q9J12tJ0fOYAVAZQSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".to_owned(),
            intel_x509: "-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\nDaVzWh5aiEx+idkSGMnX\n-----END CERTIFICATE-----\n".to_owned(),
            guardian_eth_pub_keys: vec![
                "04a1c2646197d3b93ce200cd46f4b94265d0803f712cbbbb5164027f34f18ceea2e8f1215deea31f3753d4b430c25f8cde2f730c996727e8769de50fdceb95609f".to_owned(),
                "047ec360f4fe9bd48a0109d1fe3f6aef0557c3d1df3af867de5f773f5f6190312f3e6d3c6eea5f423f138ec03ba34b051bf26d21f1255de2625f6615443c7b69e1".to_owned(),
                "049f1eff88203c2f1c25faedf674964ab292bac4c7fa2eb0aba8951d6974e83e5e5ff5fbe208a21a0d9900039d9fcad1bac6ae5c26aceca4e91be91f65a179f338".to_owned(),
                "04ac358dc89c2938747c21a65ff0fde8bd372ec5d7528ab0588837a25a125b4d2e8d068548727bb4e6e62d3033186e5245057b80f3882a3ac7887e03aae5770c0f".to_owned(),
            ],
        };

        let guardian_eth_sks = vec![
            crate::crypto::eth_keys::eth_sk_from_bytes(
                hex::decode(
                    &"65cc70c72a202c4352005934cbce69af0f11d2ba3e82b57fac2ba7bfd450d075".to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
            crate::crypto::eth_keys::eth_sk_from_bytes(
                hex::decode(
                    &"234a4c8c43efb2108a821745bcb38f336669912f053bd7dff77dfd8436c74105".to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
            crate::crypto::eth_keys::eth_sk_from_bytes(
                hex::decode(
                    &"ac8fa7a40aaea71feb340fab25bd9f551c3fe0823d8ef6ccb094990a09362f7c".to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
            crate::crypto::eth_keys::eth_sk_from_bytes(
                hex::decode(
                    &"53b2b71e29166e82342a8c9862abd49ee95e734853e16f77ede0f2a7e3ea6513".to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
        ];

        let mrenclave =
            "a72cb1ba9aa3806a22df60cbcb16a09dbaae8aae79f89c93390eb2ebe6137cd0".to_owned();
        let mrsigner =
            "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e".to_owned();
        (p, guardian_eth_sks, mrenclave, mrsigner)
    }

    #[test]
    fn test_setup_valid() {
        let (resp, g_sks, mre, mrs) = setup();
        let n = resp.bls_enc_priv_key_shares.len();
        let pk_set: blsttc::PublicKeySet =
            blsttc::PublicKeySet::from_bytes(hex::decode(&resp.bls_pub_key_set).unwrap()).unwrap();

        // keys were provisioned
        for i in 0..n {
            let g_sk = g_sks[i].clone();
            let enc_sk_bytes = hex::decode(&resp.bls_enc_priv_key_shares[i]).unwrap();
            let sk_bytes = crate::crypto::eth_keys::envelope_decrypt(&g_sk, &enc_sk_bytes).unwrap();
            let sk_share =
                blsttc::SecretKeyShare::from_bytes(sk_bytes[..].try_into().unwrap()).unwrap();
            assert_eq!(
                hex::encode(pk_set.public_key_share(i).to_bytes()),
                hex::encode(sk_share.public_key_share().to_bytes()),
            );
        }

        // evidence is valid
        let e = crate::io::remote_attestation::AttestationEvidence {
            raw_report: resp.intel_report,
            signed_report: resp.intel_sig,
            signing_cert: resp.intel_x509,
        };

        e.verify_intel_signing_certificate().unwrap();
        assert_eq!(e.get_mrenclave().unwrap(), mre);

        dbg!(&resp.signature);

        let rec_payload = e.get_report_data().unwrap();
        let payload = crate::enclave::build_validator_remote_attestation_payload(
            pk_set.clone(),
            &hex::decode(resp.signature).unwrap().into(),
            &hex::decode(resp.deposit_data_root)
                .unwrap()
                .try_into()
                .unwrap(),
            resp.bls_enc_priv_key_shares,
            resp.guardian_eth_pub_keys
                .iter()
                .map(|pk_hex| {
                    crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(pk_hex).unwrap()
                })
                .collect(),
        )
        .unwrap();

        assert_eq!(hex::encode(rec_payload), hex::encode(payload));
    }

    #[test]
    fn test_verify_custody_with_success() {
        let (resp, g_sks, mre, mrs) = setup();

        for g_sk in g_sks {
            assert!(verify_custody(g_sk, &resp).is_ok());
        }
    }

    #[test]
    fn test_verify_custody_with_fail() {
        let (resp, g_sks, mre, mrs) = setup();
        let g_sk = EthSecretKey::default();
        assert!(verify_custody(g_sk, &resp).is_err());
    }

    #[test]
    fn test_verify_remote_attestation_evidence_with_success() {
        let (resp, g_sks, mre, mrs) = setup();

        assert!(verify_remote_attestation_evidence(resp, &mre).unwrap())
    }
}
