# Secure-Signer
Secure-Signer is a remote signing tool that implements the same specs as [Web3Signer](https://consensys.github.io/web3signer/web3signer-eth2.html), making it compatible with existing consensus clients. Secure-Signer is designed to run on Intel SGX via the [Occlum LibOS](https://github.com/occlum/occlum) to protect Ethereum validators from [slashable offenses](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing). Validator keys are safeguarded in SGX's encrypted memory and the hardware enforces that Secure-Signer can only sign non-slashable messages. This reduces validator risk from slashing either from accidents or if their system is compromised.

## API
--- 
- [API Documentation](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html)

## Users 
--- 
- [User Documentation](https://pufferfinance.github.io/secure-signer/)

## Developers
---
- [Developer Documentation](https://pufferfinance.github.io/secure-signer/developers/)