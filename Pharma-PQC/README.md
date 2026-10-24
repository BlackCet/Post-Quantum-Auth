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
  SHA-256 digest of canonical packet fields: metadata, timestamp, sequence
  number, ML-KEM ciphertext, AES-GCM nonce, and encrypted payload. The
  `gateway/replay_guard.py` helper verifies that signature before enforcing a
  timestamp window and strictly increasing sequence numbers per source.

The project also contains scripts that generate synthetic files, exercise
tampering cases, and measure cryptographic and end-to-end processing time.
A separate `multi_server_auth.py` prototype demonstrates mutual post-quantum
authentication between distinct peer services.

## Project layout

| Path | Purpose |
| --- | --- |
| `hospital/` | Baseline and v2 file encryption and signing. |
| `pharma/` | Matching baseline and v2 signature verification and decryption. |
| `gateway/` | Flask forwarding prototypes, replay guard, and dashboard template. |
| `payload_auth.py` | Canonical v2 packet digest and ML-DSA verification. |
| `attacker/` | Helpers for ciphertext tampering, truncation, and metadata changes. |
| `data_generation/` | Synthetic dataset generator and sample 1 MB / 10 MB files. |
| `benchmarking/` | Baseline, v2, and TLS benchmark scripts. |
| `test_attacks.py` | Baseline tampering demonstrations, including unsigned metadata. |
| `test_v2_pipeline.py` | Local v2 round trip and tampering/replay demo. |
| `test_v2_security.py` | V2 signature-binding, replay-window, and sequence tests. |
| `test_integration.py` | Baseline HTTP integration script. |
| `test_tls_client.py` | TLS client prototype. |
| `multi_server_auth.py` | ML-DSA-authenticated, two-way ML-KEM handshake and three-peer demo. |
| `test_multi_server_auth.py` | Tests successful authentication, key agreement, and rejection cases. |
| `requirements.txt` | Python dependencies for the demos. |

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
python -m pip install -r requirements.txt
```

The v2 and multi-server authentication workflows require native `liboqs` as
well as the `liboqs-python` bindings. Depending on your platform, you may need
to build/install the native library separately; follow the `liboqs`
documentation linked above.

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

This exercises the native `oqs` implementation, the gateway replay guard,
and metadata signature verification. It writes a synthetic test input under
`Pharma-PQC/data_generation/`. Run the focused security tests with:

```sh
python -m unittest -v test_v2_security
```

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

### Multi-server post-quantum mutual authentication

`multi_server_auth.py` is a separate server-to-server handshake prototype.
Each peer has an ML-DSA-65 signing identity and a trust directory mapping peer
IDs to trusted public keys. A connection runs this exchange:

1. The initiator sends its identity, intended responder, a fresh nonce, and
   an ephemeral ML-KEM-768 public key, signed with its ML-DSA key.
2. The responder checks the initiator against its trust directory and
   verifies the signature. It replies with its identity, a fresh nonce, its
   own ephemeral ML-KEM key, an encapsulation to the initiator, and a
   signature covering the hello and challenge.
3. The initiator verifies the responder's trusted signature, decapsulates,
   encapsulates to the responder's ephemeral key, and signs the full
   transcript in its finish message, and proves possession of the derived
   key with a client key-confirmation MAC.
4. The responder verifies the signature and MAC, then decapsulates. Both
   peers derive the same session key from the two KEM secrets and handshake
   transcript; the responder returns its own key-confirmation MAC.

Run the demo and focused tests from `Pharma-PQC/`:

```sh
python multi_server_auth.py demo
python multi_server_auth.py benchmark --runs 50
python -m unittest -v test_multi_server_auth
```

The demo starts three separate local Flask services and makes authenticated
connections around a hospital/gateway/pharma loop. Each service has its own
identity and trusts the other demo identities. Credentials and the trust
directory are generated in memory for the demo; the reusable
`PeerAuthService`, `create_peer_app`, and `authenticate_peer` APIs can be
configured by an application for other peer topologies.

The `benchmark` command runs the same three services and reports, for each
peer pair, the median and p95 of two measurements: a small `/health` HTTP
round trip, and the complete mutual-authentication handshake. The HTTP
round-trip measurement is a loopback request/response time; the handshake
measurement also includes ML-KEM, ML-DSA, and key derivation work. Use
`--runs` to choose the number of measured samples per pair. These results
compare local implementation performance, not real-world network latency.
For realistic network measurements, run peers on separate machines or use a
network emulator and report its configured delay separately.

The handshake derives a session key for each peer pair, but this prototype
does not yet expose an authenticated data-transfer endpoint that uses it.
The demo runs over HTTP on loopback so it can be tried locally; real traffic
must also use correctly configured HTTPS/TLS. The application-level ML-DSA
authentication does not replace transport security.

## Payload overview

The baseline sender returns JSON-compatible values containing:

- `metadata` (filename and format)
- `ct_kem` (ML-KEM encapsulation ciphertext)
- `nonce` and `ct_aes` (AES-GCM nonce and encrypted file contents)
- `sigma` (ML-DSA signature over `ct_aes`)

The v2 sender returns `metadata`, `timestamp`, and `sequence_num`, along with
`ct_kem`, `aes_nonce`, `ct_aes`, and `sigma`. Its signature covers a digest of
the canonical metadata, timestamp, sequence number, KEM ciphertext, AES-GCM
nonce, and encrypted file contents. The shared secret and AES key are not
included in the payload.

## Security and limitations

- This is a research/demo codebase, not a reviewed secure messaging system.
  Do not use it with real patient, clinical, or otherwise sensitive data.
- The baseline intentionally leaves metadata unsigned, as demonstrated by
  `test_attacks.py`.
- The v2 replay guard is in-memory and loses its per-source sequence state
  when the process restarts. A deployed gateway would need durable,
  appropriately synchronized replay state and persistent sender sequence
  allocation.
- The v2 replay guard is a reusable validation helper, not yet wired into a
  production gateway forwarding endpoint. The caller must pass the public key
  belonging to the authenticated source from a trusted key directory.
- The multi-server handshake is a research prototype, not a reviewed or
  standardized protocol. Peer keys and the trust directory are created in
  memory in the demo; there is no persistent identity provisioning, key
  rotation, revocation, or trust-distribution mechanism.
- The multi-server demo authenticates peers and derives pairwise session keys,
  but does not yet use those keys to protect application messages. It has no
  production rate limiting, durable session storage, or denial-of-service
  controls. Do not expose its demo HTTP services to untrusted networks.
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