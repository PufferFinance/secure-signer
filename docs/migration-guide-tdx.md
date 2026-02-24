# Migration Guide: SGX/IAS → TDX/atakit

This guide is for consumers of the secure-signer, validator, and guardian services who need to update their integrations after the migration from Intel SGX (EPID attestation via Intel IAS) to Intel TDX (session-based attestation via Automata atakit).

---

## Quick Summary

| What changed | Old | New |
|---|---|---|
| TEE platform | Intel SGX inside Occlum LibOS | Intel TDX Confidential VM |
| Attestation model | Per-request Intel IAS report | Per-request CVM Agent signature (session registered on-chain) |
| Identity anchor | `MRENCLAVE` + `MRSIGNER` in keygen responses | `workload_id` (atakit-measured hash) |
| Attestation verification | Parse Intel x509 chain locally | Call `SessionRegistry.verifySessionSignature()` on-chain |
| `AttestationEvidence` fields | `raw_report`, `signed_report`, `signing_cert` | `session_id`, `signature`, `session_public_key` |
| `BlsKeygenPayload` fields | `intel_report`, `intel_sig`, `intel_x509` | `session_id`, `attestation_signature`, `session_public_key` |
| `ValidateCustodyRequest` fields | `mrenclave`, `mrsigner`, `verify_remote_attestation` | `workload_id`, `verify_session` |
| Cloud platform | Azure DC-Series (SGX) | GCP c3-standard-4 (TDX) |
| Container runtime | Ubuntu 20.04 + Occlum + SGX runtime packages | Debian Bookworm-slim, pure Docker |
| Starting the service | `occlum run /bin/secure-signer <port>` | `docker compose up` or `secure-signer` binary directly |
| Key storage path | `./etc/keys/` (Occlum FS) | `./data/keys/` (encrypted disk volume) |
| Port configuration | CLI argument only | Env var (`SECURE_SIGNER_PORT`, `VALIDATOR_PORT`, `GUARDIAN_PORT`) or CLI arg |

---

## Breaking API Changes

### 1. `AttestationEvidence` — returned in `KeyGenResponse`

This type is embedded in the response to all four keygen endpoints:
- `POST /eth/v1/keygen/secp256k1` (secure-signer)
- `POST /eth/v1/keygen/bls` (secure-signer)
- `POST /eth/v1/keygen` (guardian)
- `POST /bls/v1/keygen` (validator) — returned inside `BlsKeygenPayload`

**Old shape:**

```json
{
  "pk_hex": "0x04...",
  "evidence": {
    "raw_report": "{\"id\":\"...\",\"timestamp\":\"...\",\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"...\"}",
    "signed_report": "<base64 RSA signature>",
    "signing_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

**New shape:**

```json
{
  "pk_hex": "0x04...",
  "evidence": {
    "session_id": "0x1234...",
    "signature": "0xabcd...",
    "session_public_key": "0x04ef..."
  }
}
```

**Migration:** Replace any code that reads `raw_report`, `signed_report`, or `signing_cert` from the `evidence` object with reads of `session_id`, `signature`, and `session_public_key`.

---

### 2. `BlsKeygenPayload` — returned by `POST /bls/v1/keygen` (validator)

**Old fields (removed):**

```json
{
  "intel_report": "{ IAS JSON body }",
  "intel_sig": "<base64 RSA signature>",
  "intel_x509": "-----BEGIN CERTIFICATE-----\n..."
}
```

**New fields:**

```json
{
  "session_id": "0x1234...",
  "attestation_signature": "0xabcd...",
  "session_public_key": "0x04ef..."
}
```

**Migration:** Rename the three fields in any code that serializes or deserializes `BlsKeygenPayload`. The semantic meaning is the same — they are the attestation evidence binding the BLS keygen to the workload identity — only the names and format have changed.

---

### 3. `ValidateCustodyRequest` — sent to `POST /guardian/v1/validate-custody`

**Old shape:**

```json
{
  "keygen_payload": { ... },
  "guardian_enclave_public_key": "0x04...",
  "mrenclave": "0xdd4678fd...",
  "mrsigner": "0xabcdef12...",
  "verify_remote_attestation": true,
  "validator_index": 42
}
```

**New shape:**

```json
{
  "keygen_payload": { ... },
  "guardian_enclave_public_key": "0x04...",
  "workload_id": "<atakit workload hash>",
  "verify_session": true,
  "validator_index": 42
}
```

**Migration:**

- Replace `mrenclave` + `mrsigner` (two separate fields) with a single `workload_id` field. The workload ID is the atakit-computed hash of the Docker image + measured config — it is the TDX equivalent of MRENCLAVE.
- Rename `verify_remote_attestation` → `verify_session`.

---

### 4. Guardian route bug fix — `GET /eth/v1/keygen` now works correctly

In the old SGX codebase, the guardian binary registered `POST /eth/v1/keygen` and `GET /eth/v1/keygen` as two separate route registrations on the same path. Axum silently dropped the POST, making the ETH keygen endpoint unreachable via POST.

This is fixed in this release. `POST /eth/v1/keygen` now correctly routes to the ETH key generation handler.

**Action required:** If your client was working around this bug (e.g., calling a different URL, or handling `405 Method Not Allowed`), remove the workaround.

---

## Unaffected Endpoints

The following endpoints have **no breaking changes** — their request and response shapes are identical:

| Endpoint | Service | Notes |
|---|---|---|
| `GET /upcheck` | all | Health check, unchanged |
| `GET /eth/v1/keystores` | secure-signer, validator | List BLS keys, unchanged |
| `GET /eth/v1/keygen/secp256k1` | secure-signer | List ETH keys, unchanged |
| `GET /api/v1/eth2/publicKeys` | validator | List BLS pubkeys for VC, unchanged |
| `POST /api/v1/eth2/sign/:bls_pk_hex` | secure-signer, validator | BLS signing, unchanged |
| `POST /api/v1/eth2/deposit` | secure-signer | Deposit signing, unchanged |
| `POST /guardian/v1/sign-exit` | guardian | Voluntary exit signing, unchanged |

---

## How to Verify Attestation (New)

### Old: Client-side Intel IAS verification

Previously, clients called `KeyGenResponse::validate_eth_ra(expected_mrenclave)` or `validate_bls_ra(expected_mrenclave)` which:

1. Parsed the PEM cert chain from `signing_cert`
2. Verified the CN of the signing cert was `"Intel SGX Attestation Report Signing"`
3. Verified the CN of the root CA was `"Intel SGX Attestation Report Signing CA"`
4. Verified the chain using an OpenSSL X.509 trust store
5. Base64-decoded `isvEnclaveQuoteBody` from the `raw_report` JSON
6. Parsed the 432-byte EPID quote binary
7. Extracted `MRENCLAVE` at bytes [112..144] and compared to the expected value
8. Extracted `REPORTDATA` at bytes [368..432] and verified the public key was embedded

### New: On-chain SessionRegistry verification

Attestation verification is now done on-chain. The `session_id` in the keygen response refers to a session that was registered by a genuine TDX CVM Agent at boot.

**Verification steps:**

1. Retrieve `session_id`, `signature`, and the message (the public key bytes hex-encoded with `0x` prefix) from the keygen response
2. Call `SessionRegistry.verifySessionSignature(session_id, message, signature)` on the smart contract
3. The contract confirms:
   - The `session_id` was registered by a genuine CVM Agent backed by a valid TDX quote
   - The `signature` over `message` was produced by the session key for that `session_id`

**What `workload_id` replaces:** MRENCLAVE identified which specific enclave binary was running. The `workload_id` in `ValidateCustodyRequest` is the atakit workload hash — it identifies which Docker image + measured config was deployed. Obtain it via `atakit build-workload <name>` after building and before deploying.

> **Note:** The guardian's `verify_session_evidence()` currently performs structural validation only (checks that `session_id`, `attestation_signature`, and `session_public_key` are non-empty). Full on-chain verification via `SessionRegistry.verifySessionSignature()` is deferred to the caller. This is consistent with how the guardian previously left on-chain verification to callers.

---

## Infrastructure and Deployment Changes

### Cloud platform

| | Old | New |
|---|---|---|
| Cloud | Azure DC-Series VMs | GCP c3-standard-4 (or any TDX-capable host) |
| SGX devices | `/dev/sgx/enclave`, `/dev/sgx/provision` — must be mounted into container | Not required — service runs as a standard process inside the TDX CVM |
| AESMD service | `/var/run/aesmd` socket must be mounted | Not required |

### Starting the service

**Old (inside Occlum container):**

```bash
# Inside the container
occlum run /bin/secure-signer 9001
```

**New (plain Docker):**

```bash
# Via docker compose (recommended for atakit)
docker compose -f container/secure-signer-docker-compose.yml up

# Or directly
./secure-signer               # uses SECURE_SIGNER_PORT env var or defaults to 9001
./validator                   # uses VALIDATOR_PORT env var or defaults to 3031
./guardian                    # uses GUARDIAN_PORT env var or defaults to 3031
```

### Port configuration

All three binaries now read their port from an environment variable first, falling back to the CLI argument, then the built-in default:

| Binary | Env var | CLI arg position | Default |
|---|---|---|---|
| `secure-signer` | `SECURE_SIGNER_PORT` | 1st arg | `9001` |
| `validator` | `VALIDATOR_PORT` | 1st arg | `3031` |
| `guardian` | `GUARDIAN_PORT` | 1st arg | `3031` |

Similarly, `GENESIS_FORK_VERSION` can be set via env var for all three binaries (hex string, e.g., `00000000`).

### Docker images

**Old:** Based on `ubuntu:20.04`. Required SGX/Occlum runtime packages:
```
libsgx-epid  libsgx-quote-ex  libsgx-dcap-ql  libsgx-urts
libsgx-uae-service  libsgx-dcap-default-qpl  occlum-runtime
```

**New:** Based on `debian:bookworm-slim`. Only requires:
```
ca-certificates  libssl3
```

All three services build from a single parameterized `container/Dockerfile` using `ARG BINARY_NAME`.

### Key storage path

Keys are no longer stored inside the Occlum filesystem. They are stored on the encrypted data disk volume mounted at `/data`:

| | Old path | New path |
|---|---|---|
| BLS keys | `./etc/keys/bls_keys/` | `./data/keys/bls_keys/` |
| ETH keys | `./etc/keys/eth_keys/` | `./data/keys/eth_keys/` |
| Slashing DB | `./etc/slashing/` | `./data/slashing/` |

In Docker, `/data` is mounted as a named volume (configured as an encrypted disk in `atakit.json`). Keys persist across container restarts.

**Action required:** If you are migrating an existing deployment with keys in `./etc/keys/`, copy the key files to the new paths before starting the new service.

---

## Deploying with atakit

The project now includes `atakit.json` at the repo root, defining workloads for all three services.

### Build a workload

```bash
# Build one workload
atakit build-workload secure-signer
atakit build-workload validator
atakit build-workload guardian
```

This produces a measured artifact. The hash of this artifact is your `workload_id`.

### Deploy to GCP

```bash
atakit deploy secure-signer-tdx
atakit deploy validator-tdx
atakit deploy guardian-tdx
```

Each deployment runs on a separate `c3-standard-4` GCP instance (Intel TDX-capable) with a 10 GB encrypted data disk.

### Measured vs unmeasured configuration

atakit divides config into two categories:

| File | Purpose | Included in workload hash? |
|---|---|---|
| `container/config/secure-signer.env` | `RUST_LOG`, `SECURE_SIGNER_PORT` | Yes — changes invalidate the workload identity |
| `container/config/validator.env` | `RUST_LOG`, `VALIDATOR_PORT` | Yes |
| `container/config/guardian.env` | `RUST_LOG`, `GUARDIAN_PORT` | Yes |
| `container/additional-data/env` | `CVM_AGENT_URL` | No — operators can change this without affecting attestation |

---

## Local Development and Testing

### Testing without TDX hardware

Set `CVM_AGENT_STUB=true` to bypass the CVM Agent call. `AttestationEvidence::new()` returns an empty default (all fields empty strings), identical to how the old `#[cfg(not(feature = "sgx"))]` stub worked.

```bash
CVM_AGENT_STUB=true cargo test -- --test-threads 1
```

### Testing with a simulated CVM Agent

Use atakit's `sim-agent` to run a local mock CVM Agent that behaves like the real one (real session keys, real signatures — just not backed by TDX hardware):

```bash
# Terminal 1
atakit sim-agent   # starts mock CVM Agent on localhost:7999

# Terminal 2
cargo run --bin secure-signer   # or validator / guardian

# Verify keygen returns real session evidence
curl -X POST http://localhost:9001/eth/v1/keygen/secp256k1
```

The `CVM_AGENT_URL` env var (in `container/additional-data/env`) lets you point at a different agent endpoint.

---

## Migration Checklist

For each service you integrate with:

- [ ] **Keygen responses**: Update field names in `AttestationEvidence`: `raw_report` → `session_id`, `signed_report` → `signature`, `signing_cert` → `session_public_key`
- [ ] **BlsKeygenPayload**: Update field names: `intel_report` → `session_id`, `intel_sig` → `attestation_signature`, `intel_x509` → `session_public_key`
- [ ] **ValidateCustodyRequest**: Replace `mrenclave` + `mrsigner` with `workload_id`; rename `verify_remote_attestation` → `verify_session`
- [ ] **Attestation verification**: Replace local Intel cert chain + MRENCLAVE comparison with on-chain `SessionRegistry.verifySessionSignature()` call
- [ ] **Guardian POST /eth/v1/keygen**: Remove any workarounds for the old duplicate route bug — this endpoint now works correctly
- [ ] **Infrastructure**: Provision TDX-capable VMs (GCP c3-standard-4 or equivalent) instead of Azure DC-Series SGX VMs
- [ ] **Container startup**: Remove `--device /dev/sgx/enclave`, `--device /dev/sgx/provision`, `-v /var/run/aesmd` mounts — they are no longer needed
- [ ] **Port config**: Update deployment scripts to use `SECURE_SIGNER_PORT` / `VALIDATOR_PORT` / `GUARDIAN_PORT` env vars instead of CLI args, or confirm CLI args still work (they do, as fallback)
- [ ] **Key migration**: If migrating a live deployment, copy key files from `./etc/keys/` → `./data/keys/` before cutover
- [ ] **Client binary**: The `--mrenclave` flag in the `client` CLI is no longer meaningful — the attestation model has changed. Use `workload_id` from the atakit build output instead
