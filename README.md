# Secure-Signer
Secure-Signer is a remote signing tool for Ethereum PoS validators, with the following features:

- Follows the [Web3Signer](https://consensys.github.io/web3signer/web3signer-eth2.html) specification
- Compatible with existing Consensus clients
- Designed to run on Intel SGX via the [Occlum LibOS](https://github.com/occlum/occlum)
- Provides protection from [slashable offenses](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing)

Validator keys are safeguarded in SGX's encrypted memory and the hardware enforces that Secure-Signer can only sign non-slashable messages. This reduces validator risk from slashing either from accidents or if their system is compromised.


> **SECURE SIGNER IS UNDER DEVELOPMENT**, see [DockerHub](https://hub.docker.com/repository/docker/pufferfi/validator/general) for the latest enclave image.

--- 
## API

- [API Documentation](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html)

## Users 
- [User Documentation](https://pufferfinance.github.io/secure-signer/)

## Developers
- [Developer Documentation](https://pufferfinance.github.io/secure-signer/developers/)

## Protocols
- [Puffer Node Operator Documentation](https://docs.puffer.fi/nodes/requirements)

--- 

## Acknowledgements
Secure-Signer is funded via an [Ethereum Foundation grant](https://blog.ethereum.org/2023/02/22/allocation-update-q4-22).

The following dependencies were used and some code might have been insipired by their design decisions as well:

- [Occulum](https://github.com/occlum/occlum) LibOS - [BSD License](https://github.com/occlum/occlum/blob/master/LICENSE)


## License 
Secure Signer is released under Apache 2.0 License. See the copyright information [here](https://github.com/PufferFinance/secure-signer/blob/main/LICENSE).

