# Post-Quantum Authentication for Pharmacovigilance Data

This repository is an educational prototype for protecting pharmacovigilance
reports while they move from a hospital to a pharmaceutical receiver. It
demonstrates post-quantum key establishment and signatures alongside
authenticated symmetric encryption, and includes scripts for tampering
experiments and performance measurements.

> **Status:** Prototype only. The code is intended for experimentation and
> comparison, not for protecting real patient data or deployment in a
> production environment. See [Security and limitations](#security-and-limitations).

## What it demonstrates

The sender encrypts a file with AES-256-GCM. It derives the AES key from a
shared secret established with ML-KEM-768 using HKDF-SHA-256, then attaches an
ML-DSA-65 signature. The receiver verifies the signature, decapsulates the
shared secret, and decrypts the file.

Two implementations are provided:

- **Baseline** (`hospital/sender.py`, `pharma/receiver.py`): uses the
  `kyber-py` and `dilithium-py` Python implementations. It signs the encrypted
  bytes, but not the metadata.
- **V2** (`hospital/sender_v2.py`, `pharma/receiver_v2.py`): uses the `oqs`
  Python bindings for native `liboqs` ML-KEM and ML-DSA. Its signature covers a
  SHA-256 digest of the sorted metadata, AES-GCM nonce, timestamp, and
  ciphertext. The payload also carries a sequence number. The replay check in
  `test_v2_pipeline.py` is a demonstration helper, not a persistent or
  production gateway control.

The project also contains scripts that generate synthetic files, exercise
tampering cases, and measure cryptographic and end-to-end processing time.

## Project layout

| Path | Purpose |
| --- | --- |
| `hospital/` | Baseline and v2 file encryption and signing. |
| `pharma/` | Matching baseline and v2 signature verification and decryption. |
| `gateway/` | Flask forwarding prototypes and a dashboard template. |
| `attacker/` | Helpers for ciphertext tampering, truncation, and metadata changes. |
| `data_generation/` | Synthetic dataset generator and sample 1 MB / 10 MB files. |
| `benchmarking/` | Baseline, v2, and TLS benchmark scripts. |
| `test_attacks.py` | Baseline tampering demonstrations, including unsigned metadata. |
| `test_v2_pipeline.py` | Local v2 round trip, replay-check, and metadata-tampering demo. |
| `test_integration.py` | Baseline HTTP integration script. |
| `test_tls_client.py` | TLS client prototype. |
| `requirements.txt` | Currently empty; it does not install the Python dependencies. |

The repository also includes a `liboqs` source/build tree one directory above
this project. See [`liboqs` documentation](../pqc_builds/liboqs/README.md) for
its build and platform instructions.

## Prerequisites

- Python 3.10 or newer is recommended.
- For the baseline scripts: `cryptography`, `kyber-py`, and `dilithium-py`.
- For Flask/network prototypes: `Flask` and `requests`.
- For v2 and the native benchmarks: a compatible `liboqs` installation and
  its Python bindings (imported as `oqs`).
- For TLS scripts: a locally configured TLS server and certificate trusted by
  the client.

Create and activate a virtual environment from this directory:

```sh
cd Pharma-PQC
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography kyber-py dilithium-py Flask requests
```

The v2 workflows require native `liboqs` and its Python bindings in addition
to the baseline dependencies; installing the packages above alone is not
enough. Follow the `liboqs` documentation linked above to build/install the
native library and bindings for your platform. The checked-in
`requirements.txt` is empty, so dependencies are currently managed manually.

## Try the local demonstrations

Run commands from the `Pharma-PQC` directory so the scripts' relative paths
resolve as expected.

### Baseline attack demonstration

```sh
python test_attacks.py
```

The script checks that ciphertext modification and truncation are rejected,
then demonstrates the baseline's metadata weakness: changing the filename
does not invalidate its signature.

### V2 pipeline demonstration

```sh
python test_v2_pipeline.py
```

This exercises the native `oqs` implementation, a local replay-check helper,
and metadata signature verification. The script writes its test input under
`Pharma-PQC/data_generation/`.

### Generate additional synthetic input files

```sh
python data_generation/generate_data.py
```

This creates synthetic TXT, CSV, JSON, and PDF-like byte files at 1 MB and
10 MB in `data_generation/`. These are test inputs, not real or clinically
meaningful records.

### Run cryptographic benchmarks

```sh
python benchmarking/benchmark.py
python benchmarking/benchmark_v2.py
```

Both scripts search `data_generation/` for files named `dataset_*`. The
baseline benchmark uses the Python implementations; the v2 benchmark requires
`oqs` and `liboqs`. Results are local measurements and should not be treated
as controlled or comparable across different machines and environments.

### TLS transport prototype

The TLS example is separate from the local cryptographic pipeline. The Flask
server in `gateway/server.py` serves HTTPS on port `5000` and restricts the
server side to TLS 1.3. It loads `server_ecdsa.crt` and `server_ecdsa.key`
from the hard-coded `/mnt/d/PQA/Pharma-PQC/` path. The clients connect to
`https://localhost:5000/forward` and trust `server_ecdsa.crt`; the TLS
benchmark expects that certificate in the current working directory, while
`test_tls_client.py` uses the same hard-coded absolute path as the server.
Use a locally generated certificate and update these paths for your
environment; never use a development private key in a deployed service.

With the server and certificate configured, the client examples can be
started from this directory with:

```sh
python gateway/server.py
```

In another terminal, the TLS transmission client is:

```sh
python test_tls_client.py
```

The benchmark client is:

```sh
python benchmarking/benchmark_tls.py
```

The transmission and benchmark scripts require `oqs`, `liboqs`, and input
files in `data_generation/`. **These scripts currently do not form a
working, interoperable end-to-end pair.** The Flask server uses `kyber-py`
and creates its own ML-KEM keys at startup, while both TLS clients use native
`oqs` and create a separate gateway key pair locally. Consequently, the
server's secret key does not match the clients' encapsulation key, and the
client payload formats also differ. The server may still return an HTTP
response over TLS, but that does not demonstrate successful key recovery,
signature verification, or decryption. Coordinated key provisioning and
compatible payload handling are needed for an end-to-end demonstration.

This example demonstrates conventional certificate-authenticated TLS
transport around a payload that uses post-quantum algorithms. The configured
certificate is ECDSA; the TLS handshake itself is **not post-quantum**. The
`server_pqc.crt` and `server_pqc.key` files are not loaded by the current
server script, and their presence does not enable a post-quantum TLS handshake.

## Payload overview

The baseline sender returns JSON-compatible values containing:

- `metadata` (filename and format)
- `ct_kem` (ML-KEM encapsulation ciphertext)
- `nonce` and `ct_aes` (AES-GCM nonce and encrypted file contents)
- `sigma` (ML-DSA signature over `ct_aes`)

The v2 sender returns `metadata`, `timestamp`, and `sequence_num`, along with
`ct_kem`, `aes_nonce`, `ct_aes`, and `sigma`. Its signature covers a digest
computed from the sorted metadata, nonce, timestamp, and ciphertext. The
shared secret and AES key are not included in the payload.

## Security and limitations

- This is a research/demo codebase, not a reviewed secure messaging system.
  Do not use it with real patient, clinical, or otherwise sensitive data.
- The baseline intentionally leaves metadata unsigned, as demonstrated by
  `test_attacks.py`.
- The v2 replay check is an in-memory test helper; it does not provide durable
  replay state, concurrency control, or a complete gateway protocol.
- The v2 signature digest does not include `sequence_num` or the KEM
  encapsulation ciphertext. Do not treat those fields as authenticated by the
  sender's signature.
- Gateway scripts are prototypes and are not a ready-to-run, hardened service.
  In particular, the older gateway implementation has no configured gateway
  secret key, and the TLS client/server examples rely on local certificate
  setup. Review and configure these components before attempting network
  experiments.
- Never publish or reuse development private keys or certificates. Generate
  dedicated test credentials locally and keep private keys out of source
  control.
- The code does not provide production key storage, authorization, robust
  input validation, audit logging, or operational error handling.

## License

No project-level license is specified in this directory. The separately
included `liboqs` project has its own license and terms; consult its
documentation before redistribution.