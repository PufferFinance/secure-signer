use anyhow::{anyhow, Result};
use ethers::types::Address;
use sha3::Digest;

pub mod guardian;
pub mod secure_signer;
pub mod shared;
mod test;
pub mod types;
pub mod validator;

fn eigen_pod_address(
    eigen_pod_manager: &Address,
    eigen_pod_proxy_addr: &Address,
    beacon_proxy_bytecode: &[u8],
    eigen_pod_beacon: &Address,
) -> Result<ethers::abi::Address> {
    let init_code = ethers::abi::encode_packed(&[
        ethers::abi::Token::Bytes(beacon_proxy_bytecode.to_vec()),
        ethers::abi::Token::Bytes(ethers::abi::encode(&[
            ethers::abi::Token::Address(eigen_pod_beacon.clone()),
            ethers::abi::Token::String("".to_string()),
        ])),
    ])?;

    let salt = ethers::abi::encode(&[ethers::abi::Token::Address(eigen_pod_proxy_addr.clone())]);

    Ok(ethers::utils::get_create2_address(
        eigen_pod_manager.clone(),
        salt,
        init_code,
    ))
}

fn eigen_pod_proxy_address(
    puffer_pool_address: &Address,
    owners: &Vec<Address>,
    eigen_pod_proxy_init_code: &[u8],
) -> Result<Address> {
    let owners: Vec<ethers::abi::Token> = owners
        .clone()
        .into_iter()
        .map(|addr| ethers::abi::Token::Address(addr))
        .collect();

    // Needs array to encode properly
    let token = ethers::abi::Token::Array(owners);
    let owners_packed = ethers::abi::encode_packed(&[token])?;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&owners_packed);
    let salt = hasher.finalize();

    Ok(ethers::utils::get_create2_address(
        puffer_pool_address.clone(),
        salt,
        eigen_pod_proxy_init_code,
    ))
}

fn calculate_withdraw_credentials(
    eigen_pod_addr: Address,
) -> Result<crate::eth2::eth_types::Bytes32> {
    let encoded = ethers::abi::encode_packed(&[
        ethers::abi::Token::Bytes(vec![1]),
        ethers::abi::Token::Bytes([0; 11].to_vec()),
        ethers::abi::Token::Address(eigen_pod_addr),
    ])?;

    let Ok(bytes) = TryInto::<crate::eth2::eth_types::Bytes32>::try_into(encoded) else {
        return Err(anyhow!(
            "Failed to withdrawal credential bytes into eth Bytes32"
        ));
    };

    Ok(bytes)
}

pub fn get_withdrawal_address(
    eigen_pod_data: &types::EigenPodData,
) -> Result<crate::eth2::eth_types::Bytes32> {
    let eigen_pod_proxy_init_code = hex::decode(&eigen_pod_data.eigen_pod_proxy_init_code)?;
    let beacon_proxy_bytecode = hex::decode(&eigen_pod_data.beacon_proxy_bytecode)?;

    let eigen_pod_proxy_addr = eigen_pod_proxy_address(
        &eigen_pod_data.puffer_pool_address,
        &eigen_pod_data.pod_account_owners,
        &eigen_pod_proxy_init_code,
    )?;

    let eigen_pod_address = eigen_pod_address(
        &eigen_pod_data.eigen_pod_manager_address,
        &eigen_pod_proxy_addr,
        &beacon_proxy_bytecode,
        &eigen_pod_data.eigen_pod_beacon_address,
    )?;

    Ok(calculate_withdraw_credentials(eigen_pod_address)?)
}

#[cfg(test)]
mod tests {
    use crate::{
        enclave::{calculate_withdraw_credentials, eigen_pod_address},
        strip_0x_prefix,
    };

    use super::eigen_pod_proxy_address;

    #[test]
    fn test() {
        let bob_addr: &str = strip_0x_prefix!("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e");
        let eigen_pod_manager: &str =
            strip_0x_prefix!("0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338");
        let eigen_pod_proxy_beacon: &str =
            strip_0x_prefix!("0x5a2a4F2F3C18f09179B6703e63D9eDD165909073");
        let puffer_pool: &str = strip_0x_prefix!("0xDEb1E9a6Be7Baf84208BB6E10aC9F9bbE1D70809");

        let bob_addr = ethers::abi::Address::from_slice(&hex::decode(bob_addr).unwrap());
        let eigen_pod_manager =
            ethers::abi::Address::from_slice(&hex::decode(eigen_pod_manager).unwrap());
        let eigen_pod_proxy_beacon =
            ethers::abi::Address::from_slice(&hex::decode(eigen_pod_proxy_beacon).unwrap());
        let puffer_pool = ethers::abi::Address::from_slice(&hex::decode(puffer_pool).unwrap());

        let init_code = hex::decode("60806040526040516108e53803806108e583398101604081905261002291610460565b61002e82826000610035565b505061058a565b61003e83610100565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100fb576100f9836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e99190610520565b836102a360201b6100291760201c565b505b505050565b610113816102cf60201b6100551760201c565b6101725760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101e6816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d79190610520565b6102cf60201b6100551760201c565b61024b5760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610169565b806102827fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5060001b6102de60201b6100641760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b60606102c883836040518060600160405280602781526020016108be602791396102e1565b9392505050565b6001600160a01b03163b151590565b90565b6060600080856001600160a01b0316856040516102fe919061053b565b600060405180830381855af49150503d8060008114610339576040519150601f19603f3d011682016040523d82523d6000602084013e61033e565b606091505b5090925090506103508683838761035a565b9695505050505050565b606083156103c65782516103bf576001600160a01b0385163b6103bf5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610169565b50816103d0565b6103d083836103d8565b949350505050565b8151156103e85781518083602001fd5b8060405162461bcd60e51b81526004016101699190610557565b80516001600160a01b038116811461041957600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561044f578181015183820152602001610437565b838111156100f95750506000910152565b6000806040838503121561047357600080fd5b61047c83610402565b60208401519092506001600160401b038082111561049957600080fd5b818501915085601f8301126104ad57600080fd5b8151818111156104bf576104bf61041e565b604051601f8201601f19908116603f011681019083821181831017156104e7576104e761041e565b8160405282815288602084870101111561050057600080fd5b610511836020830160208801610434565b80955050505050509250929050565b60006020828403121561053257600080fd5b6102c882610402565b6000825161054d818460208701610434565b9190910192915050565b6020815260008251806020840152610576816040850160208701610434565b601f01601f19169190910160400192915050565b610325806105996000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610067565b610100565b565b606061004e83836040518060600160405280602781526020016102f260279139610124565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610249565b905090565b3660008037600080366000845af43d6000803e80801561011f573d6000f35b3d6000fd5b6060600080856001600160a01b03168560405161014191906102a2565b600060405180830381855af49150503d806000811461017c576040519150601f19603f3d011682016040523d82523d6000602084013e610181565b606091505b50915091506101928683838761019c565b9695505050505050565b6060831561020d578251610206576001600160a01b0385163b6102065760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610217565b610217838361021f565b949350505050565b81511561022f5781518083602001fd5b8060405162461bcd60e51b81526004016101fd91906102be565b60006020828403121561025b57600080fd5b81516001600160a01b038116811461004e57600080fd5b60005b8381101561028d578181015183820152602001610275565b8381111561029c576000848401525b50505050565b600082516102b4818460208701610272565b9190910192915050565b60208152600082518060208401526102dd816040850160208701610272565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a164736f6c634300080c000a416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c656400000000000000000000000050eef481cae4250d252ae577a09bf514f224c6c400000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024c4d66de8000000000000000000000000deb1e9a6be7baf84208bb6e10ac9f9bbe1d7080900000000000000000000000000000000000000000000000000000000").unwrap();

        let eigen_proxy =
            eigen_pod_proxy_address(&puffer_pool, &vec![bob_addr], &init_code).unwrap();

        let beacon_proxy_bytecode = hex::decode("608060405260405161090e38038061090e83398101604081905261002291610460565b61002e82826000610035565b505061058a565b61003e83610100565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100fb576100f9836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e99190610520565b836102a360201b6100291760201c565b505b505050565b610113816102cf60201b6100551760201c565b6101725760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101e6816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d79190610520565b6102cf60201b6100551760201c565b61024b5760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610169565b806102827fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5060001b6102de60201b6100641760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b60606102c883836040518060600160405280602781526020016108e7602791396102e1565b9392505050565b6001600160a01b03163b151590565b90565b6060600080856001600160a01b0316856040516102fe919061053b565b600060405180830381855af49150503d8060008114610339576040519150601f19603f3d011682016040523d82523d6000602084013e61033e565b606091505b5090925090506103508683838761035a565b9695505050505050565b606083156103c65782516103bf576001600160a01b0385163b6103bf5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610169565b50816103d0565b6103d083836103d8565b949350505050565b8151156103e85781518083602001fd5b8060405162461bcd60e51b81526004016101699190610557565b80516001600160a01b038116811461041957600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561044f578181015183820152602001610437565b838111156100f95750506000910152565b6000806040838503121561047357600080fd5b61047c83610402565b60208401519092506001600160401b038082111561049957600080fd5b818501915085601f8301126104ad57600080fd5b8151818111156104bf576104bf61041e565b604051601f8201601f19908116603f011681019083821181831017156104e7576104e761041e565b8160405282815288602084870101111561050057600080fd5b610511836020830160208801610434565b80955050505050509250929050565b60006020828403121561053257600080fd5b6102c882610402565b6000825161054d818460208701610434565b9190910192915050565b6020815260008251806020840152610576816040850160208701610434565b601f01601f19169190910160400192915050565b61034e806105996000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610067565b610100565b565b606061004e83836040518060600160405280602781526020016102f260279139610124565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610249565b905090565b3660008037600080366000845af43d6000803e80801561011f573d6000f35b3d6000fd5b6060600080856001600160a01b03168560405161014191906102a2565b600060405180830381855af49150503d806000811461017c576040519150601f19603f3d011682016040523d82523d6000602084013e610181565b606091505b50915091506101928683838761019c565b9695505050505050565b6060831561020d578251610206576001600160a01b0385163b6102065760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610217565b610217838361021f565b949350505050565b81511561022f5781518083602001fd5b8060405162461bcd60e51b81526004016101fd91906102be565b60006020828403121561025b57600080fd5b81516001600160a01b038116811461004e57600080fd5b60005b8381101561028d578181015183820152602001610275565b8381111561029c576000848401525b50505050565b600082516102b4818460208701610272565b9190910192915050565b60208152600082518060208401526102dd816040850160208701610272565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a2646970667358221220d51e81d3bc5ed20a26aeb05dce7e825c503b2061aa78628027300c8d65b9d89a64736f6c634300080c0033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564").unwrap();

        let eigen_pod = eigen_pod_address(
            &eigen_pod_manager,
            &eigen_proxy,
            &beacon_proxy_bytecode,
            &eigen_pod_proxy_beacon,
        )
        .unwrap();

        let withdrawal_credentials = calculate_withdraw_credentials(eigen_pod).unwrap();

        assert_eq!(
            format!("{:?}", eigen_proxy),
            "0x12273aac4a85d38cd19541bc284ac5c4ad7e7a2a"
        );
        assert_eq!(
            format!("{:?}", eigen_pod),
            "0x55b6420ee9d79c2bdffb81ec0479ec2b328dd58d"
        );
        assert_eq!(
            withdrawal_credentials.to_vec(),
            hex::decode("01000000000000000000000055b6420ee9d79c2bdffb81ec0479ec2b328dd58d")
                .unwrap()
        );
    }
}
