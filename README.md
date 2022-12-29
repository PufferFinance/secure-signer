# Secure-Signer
> Secure-Signer is a remote signing tool that implements the same specs as [Web3Signer](https://consensys.github.io/web3signer/web3signer-eth2.html), making it compatible with existing consensus clients. Secure-Signer is designed to run on Intel SGX via the [Occlum LibOS](https://github.com/occlum/occlum) to protect Ethereum validators from [slashable offenses](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing). Validator keys are safeguarded in SGX's encrypted memory and the hardware enforces that Secure-Signer can only sign non-slashable messages. This reduces validator risk from slashing either from accidents or if their system is compromised.

# Dev Usage:
## Installing Rust
> Running the [Warp HTTP server](https://github.com/seanmonstar/warp) requires rust 1.64, to update your rust toolchain run:
- `rustup update stable`  
- `rustup default stable`

## Docker
> TODO

## Running the server
> In one terminal, connect to the Docker container:
- `TODO`
> Start the Secure-Signer RPC server on port 3031:
- `cargo run --bin secure-signer 3031`

# Making requests
> In another terminal, make HTTP requests via curl:

## Compatible with Web3Signer

### POST /eth/v1/keystores
> Overloads [Web3Signer's API endpoint](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager/operation/KEYMANAGER_IMPORT) to securely import the BLS12-381 secret key to the enclave which may reside on an untrusted and remote server.
 
> ```
> curl -X POST localhost:3031/eth/v1/keystores -H "Content-Type: application/json"  -d '{"ct_bls_sk_hex": "0x123...", "bls_pk_hex": "0x123...", "encrypting_pk_hex": "0x123..."}'  
> ```

### GET /eth/v1/keystores
Overloads [Web3Signer's API endpoint](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager/operation/KEYMANAGER_LIST) to request the enclave list the public key of each *imported* BLS12-381 private key it is safeguarding.
> ```curl -X GET localhost:3031/eth/v1/keystores```


### POST /api/v1/eth2/sign
Compatible with [Web3Signer's API endpoint](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN) to request the Secure-Signer to use its BLS12-381 secret key for signing.
> ```curl -X GET localhost:3031/ap1/v1/eth2/sign -H "Content-Type: application/json"  -d '{"msg_hex": "0xdeadbeef", "bls_pk_hex": "0x123"}'```

> Currently accepts "BLOCK", "ATTESTATION", and "RANDAO_REVEAL" as the type. 

> TODO: implement code for types ["AGGREGATION_SLOT", "AGGREGATE_AND_PROOF", "DEPOSIT","VOLUNTARY_EXIT", "SYNC_COMMITEE_MESSAGE", "SYNC_COMMITEE_SELECTION_PROOF", "SYNC_COMMITEE_CONTRIBUTION_AND_PROOF" "VALIDATOR_REGISTRATION"]

## Additions to Web3Signer
> ### /eth/v1/keygen/eth
>> `POST`: Generates and safeguards an ETH SECP256K1 secret key in the enclave. This key can be used to facilitate the secure transfering of a BLS secret key into the enclave via [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) using [ECIES lib](https://github.com/ecies/rs).
>>> Request body: None

>>> Example Request: `curl -X POST localhost:3031/eth/v1/keygen/eth`

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

>> `GET`: Lists the public keys of each ETH SECP256K1 secret key safeguarded in the enclave.

>>> Example Request: `curl -X GET localhost:3031/eth/v1/keygen/eth`

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

> ### /eth/v1/keygen/bls
>> `POST`: Generates and safeguards a BLS12-381 secret key in the enclave. 
>>> Request body: None

>>> Example Request: `curl -X POST localhost:3031/eth/v1/keygen/bls`

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

>> `GET`: Lists the public keys of each of the *generated* BLS12-381 secret keys safeguarded in the enclave.

>>> Example Request: `curl -X GET localhost:3031/eth/v1/keygen/bls`

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```


> ### /eth/v1/remote-attestation
>> `POST`: Performs remote attestation with Intel Attestation Service, committing to the supplied public key (either SECP256K1 or BLS12-381). 
>>> Request body:
>>> ```
>>> {
>>>     "pub_key": "0x123..."
>>> }
>>> ```
>>> Example Request: `curl -X POST localhost:3031/eth/v1/remote-attestation -H "Content-Type: application/json"  -d '{"pub_key": "0x123..."}'`

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```


# TODOs
- [ ] run extensive [SSZ testing](https://github.com/ethereum/consensus-specs/blob/master/tests/formats/ssz_static/core.md) to ensure Secure-Signer correctly implemented ETH2 specs
- [ ] run extensive testing to ensure slash-resistance working locally
- [ ] implement remaining API endpoints
- [ ] connect to Teku
- [ ] run on Goerli and Shandong
- [ ] run above but in enclave environment
- [ ] dockerization / documentation