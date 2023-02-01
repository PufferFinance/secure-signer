---
layout: default
title: Secure-Signer Client
nav_order: 4
parent: Running Secure-Signer
permalink: /running/client
has_children: false
---
In this section we will guide you through the process of setting up a validator on the Goerli Testnet using the Secure-Signer client App. 

## Clone Secure-Signer
For the remainder of this guide, we assume the repo is cloned into the home (`~`) directory.
<div class="code-example" markdown="1">
```bash
git clone https://github.com/PufferFinance/secure-signer.git
```
</div>

## Using `build_secure_signer.sh`
The `build_secure_signer.sh` is a convenience script for building and running Secure-Signer. The rest of this guide assumes we are running from inside the [developer Docker container](../developers). Usage:
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~# cd secure-signer/ 
root@Puffer-Dev:~/secure-signer# ./build_secure_signer.sh -h
Build and containerize Secure-Signer.
usage: build_secure_signer.sh [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -x Run Secure-Signer on port set by -p (default 9001) (assumes this script is executed in Docker container).
    -d Build and package the DEVELOPMENT Docker Image
    -r Build and package the RELEASE Docker Image
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER.
    -h <usage> usage help
```
</div>

## Getting Secure-Signer enclave measurements
Use the `-m` flag to get the `MRENCLAVE` and `MRSIGNER` values from the Secure-Signer enclave. The `MRENCLAVE` value is important for securely importing keys! Note that this value may have changed since the time of writing this guide.

<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# ./build_secure_signer.sh -m
MRENCLAVE:
9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94
MRSIGNER:
83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
```
</div>

## Build the client App
The client App is a CLI app written in Rust to help interface with Secure-Signer during the setup phase. Run the following to compile the client App: 
<div class="code-example" markdown="1">
```bash
cargo build --release --features=dev --bin client
```
</div>

## client App usage
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# ./target/release/client -h   
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
  -w, --withdrawal-addr <WITHDRAWAL_ADDR>
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
Secure-Signer allows users to import their existing validator keystores (see the [API docs](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html#tag/Keymanager/operation/KEYMANAGER_IMPORT) for more information). Currently only keystores conforming to V3 of the [EIP-2355](https://eips.ethlibrary.io/eip-2335.html) specs are compatible. In this section, we will explain how to generate a new keystore, import it into Secure-Signer, then generate a DepositData that can be used in the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data). We strongly recommend generating BLS keys within Secure-Signer, described [in this section](#generating-a-validator-key-in-secure-signer).

## Generate a local keystore
The following command will generate a new keystore file named `bls-v3-keystore.json` in the default directory `./ss_out`. For the purposes of this demo, we will use the password `password`, but be sure to update accordingly. We assume that Secure-Signer is running on port `9001`.

<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# ./target/release/client --new-local-bls bls-v3-keystore.json --password password
- Connecting to Secure-Signer on port 9001
Saved keystore with pk: 0xa706d9bf5d6cb6f818e527d4480e71f88efa2e3ff96a26fc4a0c863bc904a53130ce64eb75db81622e62717282ef6a63
```
</div>

We can verify that the keystore downloaded:
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# cat ss_out/bls-v3-keystore.json 
{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"b8a4f94bdf18512b404ebd18146d0e57"},"ciphertext":"4ee0a2e9afe952bfc8254a3cf2dab5d511305de03d900176f5bbb067faf93b4c","kdf":"scrypt","kdfparams":{"dklen":32,"n":8192,"p":1,"r":8,"salt":"12ba84ee43bb2c3ca62fd2f47d750ef3d6fa93a7970386c292ecabebb98539c6"},"mac":"eae32d3cd0934f3aa980715ab06e03c17849ed40d72c3bf815a92ca63c1a47c1"},"id":"c7a167ce-4775-44a2-b65e-fbe86f94e1a0","version":3}
```
</div>

## Slashing Protection Database
At this point, the `bls-v3-keystore.json` is saved locally. Before we import the key into Secure-Signer we will first discuss slashing protection. You may optionally import your validator key accompanied by a slashing protection DB following [EIP3076](https://eips.ethlibrary.io/eip-3076.html).

The following command will generate a dummy database named `bls-v3-keystore-slash-protection-db.json` and for the purpose of this demo include a previously signed block with slot `1559`. Note that the `data` field accepts an array of public keys and signed material. As stated in the [API docs](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html#tag/Keymanager/operation/KEYMANAGER_IMPORT), Secure-Signer will only import the `data[0]`.

<div class="code-example" markdown="1">
```bash
echo '{
    "metadata": {
        "interchange_format_version": "5",
        "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    },
    "data": [
        {
            "pubkey": "0xa706d9bf5d6cb6f818e527d4480e71f88efa2e3ff96a26fc4a0c863bc904a53130ce64eb75db81622e62717282ef6a63",
            "signed_blocks": [
                {
                    "slot": "1559"
                }
            ],
            "signed_attestations": []
        }
    ]
}' > ss_out/bls-v3-keystore-slash-protection-db.json
```
</div>

## Import the keystore and slash protection
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# ./target/release/client --import ss_out/bls-v3-keystore.json --password password --slash-protection-path ss_out/bls-v3-keystore-slash-protection-db.json --mrenclave 0x9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94
- Connecting to Secure-Signer on port 9001
- Secure-Signer generated ETH public key: 0x0388eb64f66cb8df3590f3b49096c4deda99df952638664a1d8433ba181611f4e8
- Secure-Signer ETH public key passed remote attestation
- Securely transfered validator key to Secure-Signer: "a706d9bf5d6cb6f818e527d4480e71f88efa2e3ff96a26fc4a0c863bc904a53130ce64eb75db81622e62717282ef6a63"
- Imported BLS public key passed remote attestation
ListKeysResponse {
    data: [
        ListKeysResponseInner {
            pubkey: "0xa706d9bf5d6cb6f818e527d4480e71f88efa2e3ff96a26fc4a0c863bc904a53130ce64eb75db81622e62717282ef6a63",
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
curl -X POST localhost:9001/api/v1/eth2/sign/0xa706d9bf5d6cb6f818e527d4480e71f88efa2e3ff96a26fc4a0c863bc904a53130ce64eb75db81622e62717282ef6a63 -H "Content-Type: application/json" -d '{
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
root@Puffer-Dev:~/secure-signer# ./target/release/client --bls-keygen --mrenclave 0x9756111746cf7549c9f8c3ca180a29674196fe1300865b47936c5b71fc0a3b94
- Connecting to Secure-Signer on port 9001
- Secure-Signer generated BLS public key: 0xaf6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857
- Secure-Signer BLS public key passed remote attestation
ListKeysResponse {
    data: [
        ListKeysResponseInner {
            pubkey: "0xaf6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857",
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

Secure-Signer now safeguards the private key corresponding to the public key `0xaf6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857` with a slash protection DB initialized to `slot=0`, `source_epoch=0`, and `target_epoch=0`.

### Network Config
Before we generate our DepositData to register our validator keys, there are some parameters that change depending on the target Testnet. By default the client App uses the `conf/network_config.json` file which is configured to work with the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data). To work with a different Testnet, either modify this file or supply a new file using the flag `--config <path_to_your_network_config>`.

# Register validator keys
To register your validator, you must use your validator key to sign off on a DepositData. The following command will make the client App request Secure-Signer to generate a `deposit_data.json` file to the default directory `ss_out` using the public key `0xaf6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857`. The client App generates withdrawal credentials using the `ETH1_ADDRESS_WITHDRAWAL_PREFIX` (0x01) described in the [Capella specs](https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#new-process_bls_to_execution_change), which requires a 20B hex-encoded ETH address. In this example, we're setting partial withdrawals to send ETH to `0x4D68568B8D4E6244233c685B48fEa619621B78D2`.

<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# ./target/release/client --deposit --validator-pk-hex 0xaf6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857 --execution-addr 0x4D68568B8D4E6244233c685B48fEa619621B78D2
- Connecting to Secure-Signer on port 9001
Using withdrawal_credentials: 0x0100000000000000000000004D68568B8D4E6244233c685B48fEa619621B78D2
Writing DepositData to "./ss_out/deposit_data.json"
```
</div>

Verify the DepositData was generated:
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~/secure-signer# cat ss_out/deposit_data.json 

        [{
            "pubkey": "af6f9c1249a4e0e30c73b5df4fdce4b76f0624c5508ab6484c4fb670fe2c9c143287efc289e146b763e87fd3b3dd5857",
            "withdrawal_credentials": "0100000000000000000000004d68568b8d4e6244233c685b48fea619621b78d2",
            "amount": 32000000000,
            "signature": "a2b37e87ee93762dff1784845d28a73a711a244edce9311686b05e6079f95b25a6bd1fa4360b00871cc784b7521aef43181910b9c2b4527a18c5a72f9e7a1a4014e33ea1dd5d8a479ba05ea9f200ee017c167034c09397dbbb52a4931b8947c2",
            "deposit_message_root": "b15d279068b7fd017b604fdbcceb2d913e20367578c00d05df68c8fe5f1fc67c",
            "deposit_data_root": "f7aaec6ce6f04e2b86d5341140c99befe432413ac0081a3c2283056633bfeda9",
            "fork_version": "00001020",
            "network_name": "goerli",
            "deposit_cli_version": "2.3.0"
        }]
```
</div>

If on a remote server, you can grab this file by running the following with your username and IP:
<div class="code-example" markdown="1">
```bash
scp user@12.345.678.910:~/secure-signer/ss_out/deposit_data.json .
```
</div>

Navigate to the [Goerli launchpad](https://goerli.launchpad.ethereum.org/en/upload-deposit-data) and upload your `deposit_data.json` file:

![upload-deposit-data](../images/upload_deposit_data.png)

Congrats! Continue to follow the launchpad's instructions and your validator will make it onto the Testnet. 