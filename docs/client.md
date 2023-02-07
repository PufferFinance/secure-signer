---
layout: default
title: Secure-Signer Client
nav_order: 4
parent: Running Secure-Signer
permalink: /running/client
has_children: false
---
In this section we will guide you through the process of setting up a validator on the Goerli Testnet using the Secure-Signer client App that is bundled in the `pufferfinance/secure_signer:latest` container image. It is assumed that you have completed installation and can run Secure-Signer as documented [here](../running).

## Getting Secure-Signer enclave measurements
The Secure-Signer enclave's `MRENCLAVE` value is necessary so that you know you are interfacing only with the correct version of Secure-Signer. This is extremely important to verify before importing any of your keys! Note that the `MRENCLAVE` value used in this guide may have changed since the time of writing. To fetch this value run:

<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec secure_signer_container /bin/bash -c  "cat MRENCLAVE"
9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94
```
</div>
Thus the `MRENCLAVE` value for this version of Secure-Signer is `0x9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94`.

## Client App usage
The client App is a CLI app written in Rust to help interface with Secure-Signer during the setup phase. Run the following to get its usage:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "./client -h"
Secure-Signer Client Interface

Usage: client [OPTIONS]

Options:
  -p, --port <PORT>
          The port that Secure-Signer is exposing [default: 9001]
  -o, --outdir <OUTDIR>
          The path to the directory to save Secure-Signer outputs [default: ./ss_out]
  -b, --bls-keygen
          Requests Secure-Signer to generate BLS key perform remote attestation [requires --mrenclave]
  -l, --list
          Requests Secure-Signer to list all of its keys
      --import <IMPORT>
          The path to a BLS keystore [requires --password, --mrenclave]
      --password <PASSWORD>
          The password to the keystore
      --slash-protection-path <SLASH_PROTECTION_PATH>
          The path to EIP-3076 .JSON
  -d, --deposit
          Request Secure-Signer to generate a DepositData [requires validator-pk-hex, --withdrawal-addr]
  -v, --validator-pk-hex <VALIDATOR_PK_HEX>
          The validator public key in hex
  -e, --execution-addr <EXECUTION_ADDR>
          The ETH address for withdrawals
      --mrenclave <MRENCLAVE>
          The expected MRENCLAVE value
  -c, --config <CONFIG>
          The path to the JSON network config file [default: ./conf/network_config.json]
  -n, --new-local-bls <NEW_LOCAL_BLS>
          Locally generates a BLS keystore with the supplied name [requires --password]
  -h, --help
          Print help
  -V, --version
          Print version
```
</div>


# Importing a validator key
Secure-Signer allows users to import their existing validator keystores (see the [API docs](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html#tag/Keymanager/operation/KEYMANAGER_IMPORT) for more information). Currently only keystores conforming to V3 of the [EIP2355](https://eips.ethlibrary.io/eip-2335.html) specs are compatible. In this section, we will explain how to generate a new keystore, import it into Secure-Signer, then generate a DepositData that can be used in the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data). We strongly recommend generating BLS keys within Secure-Signer, described [in this section](#generating-a-validator-key-in-secure-signer).

## Generate a local keystore
The following command will generate a new keystore file named `bls-v3-keystore.json` in the default directory `./ss_out`. For the purposes of this demo, we will use the password `password`, but be sure to update accordingly. We assume that Secure-Signer is running on port `9001`, which is the default port used by the client.

<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "./client --new-local-bls bls-v3-keystore.json --password password"
- Connecting to Secure-Signer on port 9001
Saved keystore with pk: 0xaf4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3
```
</div>

We can verify that the keystore downloaded:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "cat ss_out/bls-v3-keystore.json"
{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"4316071448aa82f2f8ba87b1e77ba74b"},"ciphertext":"903092827a3fd52a44ba795a557a94e483ae8025b207a6e67a908b699ddb8c3a","kdf":"scrypt","kdfparams":{"dklen":32,"n":8192,"p":1,"r":8,"salt":"7ac3a9575d1da1d44fd0e3e1e78775610be775494debb95935414975c7c40f94"},"mac":"5690add8588e415dbd9c518b9caf2f2fa5b72b12369fa3030a7b7bfb694b26cf"},"id":"459f5b73-8a93-4529-babc-daf1b9e62aad","version":3}
```
</div>

## Slashing Protection Database
At this point, the `bls-v3-keystore.json` is saved locally. Before we import the key into Secure-Signer we will first discuss slashing protection. You may optionally import your validator key accompanied by a slashing protection DB following [EIP3076](https://eips.ethlibrary.io/eip-3076.html).

The following command will generate a dummy database named `bls-v3-keystore-slash-protection-db.json` and for the purpose of this demo include a previously signed block with slot `1559`. Note that the `data` field accepts an array of public keys and signed material. As stated in the [API docs](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html#tag/Keymanager/operation/KEYMANAGER_IMPORT), Secure-Signer will only import the `data[0]`.

<div class="code-example" markdown="1">
```bash
docker exec -w /home secure_signer_container /bin/bash -c "echo  '{
    \"metadata\": {
        \"interchange_format_version\": \"5\",
        \"genesis_validators_root\": \"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673\"
    },
    \"data\": [
        {
            \"pubkey\": \"0xaf4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3\",
            \"signed_blocks\": [
                {
                    \"slot\": \"1559\"
                }
            ],
            \"signed_attestations\": []
        }
    ]
}' > ss_out/bls-v3-keystore-slash-protection-db.json"
```
</div>

Verify our dummy slash protection was written:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "cat ss_out/bls-v3-keystore-slash-protection-db.json"
{
    "metadata": {
        "interchange_format_version": "5",
        "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    },
    "data": [
        {
            "pubkey": "0xaf4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3",
            "signed_blocks": [
                {
                    "slot": "1559"
                }
            ],
            "signed_attestations": []
        }
    ]
}
```
</div>

## Import the keystore and slash protection
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "./client --import ss_out/bls-v3-keystore.json --password password --slash-protection-path ss_out/bls-v3-keystore-slash-protection-db.json --mrenclave 0x9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94"
- Connecting to Secure-Signer on port 9001
- Secure-Signer generated ETH public key: 0x03c7c44c5091fd60773003d40fa489a5ded9e83d99c2e169d70c084ed8cfef19e7
- Secure-Signer ETH public key passed remote attestation
- Securely transfered validator key to Secure-Signer: "af4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3"
- Imported BLS public key passed remote attestation
ListKeysResponse {
    data: [
        ListKeysResponseInner {
            pubkey: "0xaf4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3",
        },
    ],
}

```
</div>

### Breaking down what happened
- We supplied the `--mrenclave` flag with the value obtained from running `./build_secure_signer.sh -m`
- We specified paths to our keystore and slash protection.
- We supplied the password to our keystore.
- The client App requested Secure-Signer to generate a new ETH keypair then perform Remote Attestation. The attestation evidence was written to `ss_out/eth-ra-evidence.json`.
- The client App verified the validity of the attestation evidence gaining trust in this Secure-Signer instance. The verification process required that the report's `MRENCLAVE` value matched the expected, the evidence was signed by Intel, and the ETH public key was committed to in the report.
- The client App encrypted the keystore password with the ETH public key, then imported the keystore, encrypted password, and slash protection into Secure-Signer.
- Secure-Signer decrypted the keystore password and saved the validator key.
- The client App requested Secure-Signer to perform Remote Attestation on the imported validator key.
- The client App similarly verified the attestation evidence, asserting that the expected BLS public key was committed to in the report (saved to `ss_out/bls-ra-evidence.json`).
- The client App requested Secure-Signer to list all of the validator keys that have been imported.


## Attempt to sign a slashable block 
At this point, Secure-Signer is loaded with our validator key and slash protection DB! We can verify that Secure-Signer prevents slashing by sending a block proposal with a non-increasing slot of `1337`.
Note, the following should not be attempted on real keys and is solely for demonstration purposes. In practice, all signing material (minus deposits) passed to Secure-Signer should originate from your consensus client.
<div class="code-example" markdown="1">
```bash
curl -X POST localhost:9001/api/v1/eth2/sign/0xaf4d253411e7a2ddc28fc514e551070abc291bc5a5e5fbc4b6bc5f5282f03ce150b363d325437fcfde0df8d22558dcf3 -H "Content-Type: application/json" -d '{
    "type": "BLOCK_V2",
    "fork_info":{
        "fork":{
           "previous_version":"0x80000070",
           "current_version":"0x80000071",
           "epoch":"750"
        },
        "genesis_validators_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
     },
    "signingRoot": "0x2ebfc2d70944cc2fbff6d67c6d9cbb043d7fbe0a660d248b6e666ce110af418a",
    "beacon_block": {
        "version": "BELLATRIX",
        "block_header": {
            "slot": "1337",
            "proposer_index": "0",
            "parent_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "state_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "body_root":"0xcd7c49966ebe72b1214e6d4733adf6bf06935c5fbc3b3ad08e84e3085428b82f"
        }
    }
}'
```
</div>
This returns the error: ```{"error":"block_header.slot <= previous_block_slot, Signing operation failed due to slashing protection rules"}```

This concludes the guide on how to import keys into Secure-Signer. The next section will document the simpler and more secure method of generating validator keys inside Secure-Signer. 

# Generating a validator key in Secure-Signer
Generating a new validator key in Secure-Signer is easy. Run the following:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "./client --bls-keygen --mrenclave 0x9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94"
- Connecting to Secure-Signer on port 9001
- Secure-Signer generated BLS public key: 0x8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7
- Secure-Signer BLS public key passed remote attestation
ListKeysResponse {
    data: [
        ListKeysResponseInner {
            pubkey: "0x8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7",
        },
    ],
}
```
</div>

### Breaking down what happened
- We supplied the `--mrenclave` flag with the value obtained from running `./build_secure_signer.sh -m`
- The client App requested Secure-Signer to generate a new BLS keypair then perform Remote Attestation. The attestation evidence was written to `ss_out/bls-ra-evidence.json`.
- The client App verified the validity of the attestation evidence gaining trust in this Secure-Signer instance. The verification process required that the report's `MRENCLAVE` value matched the expected, the evidence was signed by Intel, and the validator public key was committed to in the report.
- The client App requested Secure-Signer to list all of the validator keys that have been generated.

Secure-Signer now safeguards the private key corresponding to the public key `0x8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7` with a slash protection DB initialized to `slot=0`, `source_epoch=0`, and `target_epoch=0`.

### Network Config
Before we generate our DepositData to register our validator keys, there are some parameters that change depending on the target Testnet. By default the client App uses the `conf/network_config.json` file which is configured to work with the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data). To work with a different Testnet, either modify this file or supply a new file using the flag `--config <path_to_your_network_config>`.

# Register validator keys
To register your validator, you must use your validator key to sign off on a DepositData. The following command will make the client App request Secure-Signer to generate a `deposit_data.json` file to the default directory `ss_out` using the public key `0x8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7`. The client App generates withdrawal credentials using the `ETH1_ADDRESS_WITHDRAWAL_PREFIX` (0x01) described in the [Capella specs](https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#new-process_bls_to_execution_change), which requires a 20B hex-encoded ETH address. In this example, we're setting partial withdrawals to send ETH to `0x4D68568B8D4E6244233c685B48fEa619621B78D2`.

<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "./client --deposit --validator-pk-hex 0x8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7 --execution-addr 0x4D68568B8D4E6244233c685B48fEa619621B78D2"
- Connecting to Secure-Signer on port 9001
Using withdrawal_credentials: 0x0100000000000000000000004D68568B8D4E6244233c685B48fEa619621B78D2
Writing DepositData to "./ss_out/deposit_data.json"
```
</div>

You can grab this `deposit_data.json` file by running the following:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -w /home secure_signer_container /bin/bash -c "cat ss_out/deposit_data.json" > ~/deposit_data.json                                                                       
puffer@Puffer-Dev:~$ cat ~/deposit_data.json 

        [{
            "pubkey": "8289a5b32c66cd1f7de338855bc7b70897402a42f24070f9ad62423c76c05f001d560975d40106200b5cb9176488a2c7",
            "withdrawal_credentials": "0100000000000000000000004d68568b8d4e6244233c685b48fea619621b78d2",
            "amount": 32000000000,
            "signature": "b465d3cf1e108aed4a627bca2cffa482218b1e99bdd057b4625a0dee8138f33820af9a42404b732ab4583ae62ef74a350ac5569f23e8d7ecca86d7c8e36daea605157be6b3fe4bb4eb172adb2b9eced5143e34388f68ff95ea73381df234306d",
            "deposit_message_root": "eadccf9293ad7bb7d739b287a5d6dd2ed4f076a9f72d696b1a41c8220d096389",
            "deposit_data_root": "8039153a6874062149b6a426a12f5344e89e266dcc454569c79487a8bdcd48e4",
            "fork_version": "00001020",
            "network_name": "goerli",
            "deposit_cli_version": "2.3.0"
        }]
```
</div>

If Secure-Signer is running on a remote server, you can fetch the file on your local machine by running the following with your username and IP:
<div class="code-example" markdown="1">
```bash
scp user@12.345.678.910:~/deposit_data.json .
```
</div>

Navigate to the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data) and upload your `deposit_data.json` file:

![upload-deposit-data](../images/upload_deposit_data.png)

Congrats! Continue to follow the launchpad's instructions and your validator will make it onto the Testnet. 