# Secure-Signer
Secure-Signer is a remote signing tool for Ethereum PoS clients, with the following features:

- Follows the [Web3Signer](https://consensys.github.io/web3signer/web3signer-eth2.html) specification
- Compatible with existing Consensus clients
- Designed to run on Intel SGX via the [Occlum LibOS](https://github.com/occlum/occlum)
- Secure Slash protectection from common [slashable offenses](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing)

Validator keys are safeguarded in SGX's encrypted memory and the hardware enforces that Secure-Signer can only sign non-slashable messages. This reduces validator risk from slashing either from accidents or if their system is compromised.


> **SECURE SIGNER IS UNDER DEVELOPMENT AND SHOULD NOT BE USED FOR PRODUCTION**, unless you know what you are doing. 

--- 
## API

- [API Documentation](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html)

## Users 
- [User Documentation](https://pufferfinance.github.io/secure-signer/)

## Developers
- [Developer Documentation](https://pufferfinance.github.io/secure-signer/developers/)

--- 

## Roadmap
- [x] Open source the alpha code
- [ ] Formal verification specification
- [ ] Convert modules into their own crates

### TODO
- [ ] Code review and Audit
- [ ] Support DCAP remote attestation
- [ ] API endpoint to read current SlashProtection database

### Known Limitations / Issues
- [ ] Limited to only 1 key at a time
   - [ ] footgun: if you import an existing key, you expose yourself to slashing risk. 


--- 
## Acknowledgement

Secure Signer uses the following dependencies with the mentioned licenses, some code might have been insipired by their design decisions as well.

- [Occulum](https://github.com/occlum/occlum) LibOS - [BSD License](https://github.com/occlum/occlum/blob/master/LICENSE)



## License 
Secure Signer is released under Apache 2.0 License. See the copyright information [here](https://github.com/PufferFinance/secure-signer/blob/main/LICENSE).

