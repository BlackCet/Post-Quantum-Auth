# Post-Quantum Authentication Demo

A Docker-based demo for exploring post-quantum cryptography (PQC) in an authenticated file-transfer workflow. A Hospital client submits a protected packet through a mutual-TLS endpoint; a Pharma client retrieves it from a gateway cluster and verifies and decrypts it. The project includes application-layer PQC, post-quantum TLS, classical TLS controls, and repeatable benchmarks.

> This repository is an experimental, local demo. It is not a production-ready medical records system or a production security configuration.

## What is included

- **Packet protection:** ML-KEM-768 establishes a shared secret for AES-GCM encryption, and ML-DSA-65 provides signatures.
- **Authenticated packet mode:** The improved format signs canonical packet metadata, timestamp, sequence number, nonce, and ciphertext. Gateways reject stale or replayed packets using shared Redis-backed state.
- **TLS profiles:** Compare classical mutual TLS, application-layer PQC over classical TLS, and TLS 1.3 with the X25519MLKEM768 hybrid key-exchange group and ML-DSA-65 certificates.
- **Gateway cluster:** Three Flask gateways share packet state through Redis and sit behind an Nginx TLS terminator. The proxy also uses mutual TLS to authenticate its connections to the gateways.
- **Dashboards and benchmarks:** Inspect application crypto timings and network measurements, including handshake resumption, request latency, throughput, and resource usage.

The baseline application implementation uses the Python PQC libraries. The improved implementation uses native `liboqs` for ML-KEM-768 and ML-DSA-65 and enables authenticated packet checks. These are separate key sets and packet formats.

## Requirements

- Docker Desktop with Docker Compose v2
- PowerShell for the commands below

The application image builds OpenSSL 3.5+ and native `liboqs`. Building it for the first time can take several minutes. You do not need to install or change the host OpenSSL installation.

## Quick start

Run these commands from the repository root in PowerShell. Generate both application key sets and the local TLS certificates first; the private keys and generated certificates are intentionally ignored by Git.

```powershell
docker compose build
docker compose --profile tools run --rm --entrypoint python pqc-keygen keygen.py --implementation both
docker compose --profile tools run --rm tls-certgen
docker compose up -d redis gateway-1 gateway-2 gateway-3 tls-proxy dashboard
docker compose ps
```

The TLS endpoint is `https://localhost:5001`. The local dashboards are:

- Application crypto comparison: <http://localhost:5002/dashboard>
- TLS network benchmark reports: <http://localhost:5002/tls-dashboard>

Exercise the sample transfer with the bundled data:

```powershell
docker compose run --rm hospital
docker compose run --rm pharma
```

Stop the services when finished:

```powershell
docker compose down --remove-orphans
```

## Benchmarking

The default network benchmark runs the post-quantum TLS profile and writes reports under `benchmark-output/`:

```powershell
docker compose --profile tools run --rm benchmark
```

The network benchmark supports three modes:

- `pq-hybrid-tls`: TLS 1.3 with hybrid X25519MLKEM768 key exchange.
- `classical-mtls`: classical mutual TLS, used as a control.
- `application-pqc`: application-layer PQC packets sent over classical mutual TLS.

For example, run a small application-PQC check against the classical profile:

```powershell
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml --profile tools run --rm benchmark python analysis/benchmark.py --network --mode application-pqc --runs 2 --sizes 1 --filetypes txt
```

See [TLS.md](TLS.md) for certificate setup details, profile switching, improved-mode configuration, report fields, and full benchmark commands.

## Tests

With the project dependencies installed in your Python environment, run the unit tests with:

```powershell
python -m unittest discover -s tests
```

## Repository map

- `hospital/` and `pharma/`: client workflows
- `gateway/`: API, Redis-backed storage, and dashboards
- `crypto_backend.py` and `packet_auth.py`: PQC implementations and authenticated packet fields
- `analysis/`: application and network benchmark runners
- `docker/` and `docker-compose*.yaml`: TLS profiles, proxy configuration, and local services
- `tests/`: unit tests

## Security notes

This setup is intended for local experimentation only. The included Redis configuration has no TLS or authentication, and generated demo credentials must not be reused in production. Real deployments need managed certificate and key rotation, authenticated and encrypted Redis connections, appropriate network controls, and a security review of the complete system. Benchmark figures depend on host and container load and should be treated as comparative observations, not performance guarantees.