use ethers::types::TxHash;

pub mod guardian;
pub mod secure_signer;
mod test;
pub mod validator;

#[derive(Clone, Debug)]
pub struct BLSKeygenPayload {
    bls_pub_key: String,
    signature: String,
    deposit_data_root: TxHash,
    bls_enc_priv_key_shares: Vec<String>,
    bls_pub_key_shares: Vec<String>,
    intel_sig: String,
    intel_report: String,
    intel_x509: String,
}

#[derive(Clone, Debug)]
pub struct EigenPodData {
    eigen_pod_manager_address: ethers::abi::Address,
    eigen_pod_proxy_address: ethers::abi::Address,
    eigen_pod_beacon_address: ethers::abi::Address,
    beacon_proxy_bytecode: Vec<u8>,
}

pub fn calculate_withdraw_address(eigen_pod_data: EigenPodData) -> ethers::abi::Address {
    let EigenPodData {
        eigen_pod_manager_address,
        eigen_pod_proxy_address,
        eigen_pod_beacon_address,
        beacon_proxy_bytecode,
    } = eigen_pod_data;

    let proxy_init_code = ethers::abi::encode_packed(&[
        ethers::abi::Token::Bytes(beacon_proxy_bytecode),
        ethers::abi::Token::Bytes(ethers::abi::encode(&[
            ethers::abi::Token::Bytes(eigen_pod_beacon_address[..].to_vec()),
            ethers::abi::Token::Bytes(b"".to_vec()),
        ])),
    ])
    .unwrap();

    let proxy_address = ethers::utils::get_create2_address(
        eigen_pod_manager_address,
        eigen_pod_proxy_address,
        proxy_init_code,
    );

    let withdrawal_init_code = ethers::abi::encode_packed(&[
        ethers::abi::Token::Bytes(vec![1u8]),
        ethers::abi::Token::Bytes([0u8; 11].to_vec()),
        ethers::abi::Token::Bytes(proxy_address[..].to_vec()),
    ])
    .unwrap();

    ethers::utils::get_create2_address(
        proxy_address,
        proxy_address.to_fixed_bytes(),
        withdrawal_init_code,
    )
}
