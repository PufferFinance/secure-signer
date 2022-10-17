# datafeeds
> An oracle service for providing data feeds on-chain.

# Key Distribution Protocol
> - A group of `n` `Workers` and one `Leader` form a `PON` (Portal Oracle Network).
> - Each `Worker` `W[i]` generates an ephemeral SECP256K1 secret key `SK[i]`, then commits to the corresponding public key `PK[i]` by including it as report data during remote attestation with Intel. The remote attestation procedure yields attestation evidence `AV[i]`. Each `W[i]` will save `SK[i]` in the their enclave's memory until it is refreshed after a timeout (e.g., daily).
> - Each `Worker` broadcasts `AV[i]` to the `Leader`.
> - Upon receiving and verifying all `n` attestation evidence `AV[i]`, the `Leader` securely generates `n` BLS secret keys `BLS_SK[i]` in their enclave.
> - The `Leader` produces `CT_BLS_SK[i]` by encrypting `BLS_SK[i]` with a symmetric key `K[i]`, where `K[i]` is derived via ECDH from the `PK[i]` embedded in `AV[i]`.  
> - The `Leader` derives and saves the aggregate BLS public key `AGG_PK`, then distributes `CT_BLS_SK[i]` to each `Worker`.
>- Each `W[i]` can compute then save `BLS_SK[i]` by first deriving `K[i]` via ECDH from their saved `SK[i]`, then decrypting `CT_BLS_SK[i]` with it.
>- At this point, the `Leader` has saved an aggregate BLS public key `AGG_PK` and the enclave code ensures that it has forgotten each `BLS_SK[i]`. Each `Worker` has saved a BLS secret key `BLS_SK[i]` in their enclave memory which can only be used during the oracle service. In order to generate a valid aggregeate signature, all `n` `Workers` must sign off on the message.

# APIs
> ### /portal/v1/keygen/eth
>> `POST`: Generates an ETH SECP256K1 secret key in the enclave. 
>>> Request body: None

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

>> `GET`: Lists the public keys of each ETH SECP256K1 secret key safeguarded in the enclave.
>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

> ### /portal/v1/keygen/bls
>> `POST`: Generates a BLS12-381 secret key in the enclave. 
>>> Request body: None

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

>> `GET`: Lists the public keys of each of the *generated* BLS12-381 secret keys safeguarded in the enclave.
>>> Response body: 
>>> ```
>>> {TODO}
>>> ```


> ### /portal/v1/keystores/bls
>> `POST`: Imports a BLS12-381 secret key to the enclave. 
>>> Request body:
>>> ```
>>> {TODO}
>>> ```

>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

>> `GET`: Lists the public keys of each of the *imported* BLS12-381 secret keys safeguarded in the enclave.
>>> Response body: 
>>> ```
>>> {TODO}
>>> ```

