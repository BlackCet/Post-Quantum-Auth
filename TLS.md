# Multi-gateway TLS and PQC benchmark

This Docker demo runs three Flask gateways behind an Nginx TLS terminator.
Nginx requires mutual TLS, balances requests across the gateways, and uses a
shared TLS session cache/ticket key so a resumed handshake can reach any
backend. The proxy-to-gateway connection is also TLS 1.3 mutual TLS: Nginx
verifies each gateway certificate and presents a dedicated proxy client
certificate, which gateways require and validate. Gateways keep packet state
in Redis, so a client can submit through one gateway and retrieve through
another. The host Python installation is not changed.

The PQ profile uses TLS 1.3, the X25519MLKEM768 hybrid key-exchange group, and
ML-DSA-65 certificates. A classical P-256 mTLS profile is included for
comparison. Both profiles use the same test data, routes, and run count.
OpenSSL 3.5 or later is installed in the application image.

## Generate test certificates and start the PQ cluster

Run these commands from the repository root in PowerShell:

```powershell
docker compose --profile tools run --rm tls-certgen
docker compose up --build -d redis gateway-1 gateway-2 gateway-3 tls-proxy
docker compose ps
```

The certificate command creates separate frontend and backend PKIs for the PQ
and classical profiles under `tls-certs\`. Each gateway has its own backend
server certificate; the proxy has a separate client certificate. These
credentials are ignored by Git; do not reuse them outside this controlled
demo. The cluster exposes the TLS endpoint on
`https://localhost:5001`.

## Open the dashboards

After starting the cluster, start the local dashboard service:

```powershell
docker compose up -d dashboard
```

Open `http://localhost:5002/dashboard` for the local baseline/improved crypto
comparison and `http://localhost:5002/tls-dashboard` for the network reports.
The dashboard reads `benchmark_results.json`,
`benchmark_results_improved.json`, and reports in `benchmark-output\` directly
from the host workspace. The service binds only to localhost.

To exercise the application flow, submit a sample and retrieve it:

```powershell
docker compose run --rm hospital
docker compose run --rm pharma
```

Both clients authenticate with their own client certificates. The Pharma
client retrieves and verifies/decrypts a packet using the shared Redis-backed
state.

## Run the network benchmarks

The full PQ TLS workload runs five fresh/resumed request pairs for 1 MB and
10 MB datasets across TXT, CSV, JSON, and PDF. It writes JSON reports to
`benchmark-output\`:

```powershell
docker compose --profile tools run --rm benchmark
```

The benchmark caches generated inputs in
`benchmark-output\datasets\`. The SHA-256 field
`original_payload_sha256` lets you confirm that different TLS profiles used
identical content. To run a smaller smoke workload:

```powershell
docker compose --profile tools run --rm benchmark python analysis/benchmark.py --network --mode pq-hybrid-tls --runs 2 --sizes 1 --filetypes txt
```

### Classical TLS control

Stop the current profile before switching, then start the same cluster with
the classical TLS overlay:

```powershell
docker compose down --remove-orphans
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml up --build -d redis gateway-1 gateway-2 gateway-3 tls-proxy
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml --profile tools run --rm benchmark python analysis/benchmark.py --network --mode classical-mtls --runs 5 --sizes 1 10 --filetypes txt csv json pdf
```

### Application-layer PQC over classical TLS

This mode sends the existing ML-KEM/AES-GCM/ML-DSA envelope over the
classical mTLS connection. Run it against the same cached datasets:

```powershell
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml --profile tools run --rm benchmark python analysis/benchmark.py --network --mode application-pqc --runs 5 --sizes 1 10 --filetypes txt csv json pdf
```

Switch back to the PQ TLS profile by stopping the overlay and starting the
base cluster again:

```powershell
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml down --remove-orphans
docker compose up --build -d redis gateway-1 gateway-2 gateway-3 tls-proxy
```

Each report defaults to `benchmark-output\tls-<mode>.json`; `--output` can
select another file. In every mode, `runs` is the number of request pairs.
Each pair contains a fresh TLS handshake/request and a resumed
TLS handshake/request, so `successful_requests` can be up to twice `runs`.
Percentile summaries contain median, nearest-rank p95, minimum, and maximum.

## Reading the results

- `tls_fresh_handshake_latency_ms` and `tls_resumed_handshake_latency_ms`
  report the handshake phase separately; resumption attempt/success counters
  and handshake success/failure rates accompany them.
- `request_rtt_ms` includes the request and response after the handshake.
  `request_rtt_by_handshake_ms` separates fresh from resumed requests.
- `payload_throughput_mbps` is based on the original input bytes;
  `wire_throughput_mbps` includes TLS wire traffic.
- `tls_handshake_bytes_sent/received` and
  `tls_application_phase_bytes_sent/received` are disjoint socket-byte
  categories. Application-phase bytes include HTTP and any post-handshake TLS
  records. `total_bytes_transferred` sums each observed client socket byte
  once.
- `application_layer_overhead_bytes` is envelope growth over the original
  payload (nonzero for `application-pqc`). `communication_overhead_bytes`
  subtracts successful original payload bytes from total observed wire bytes,
  so it includes handshakes, TLS records, HTTP framing, responses, and any
  application-envelope growth. These are distinct measures, not additive
  counters.
- The existing crypto timing fields remain available. Receiver-side
  verification/decryption timings are populated in `application-pqc`; they
  are null when the TLS profile transports raw payloads.
- `verified` and `plaintext_match` report correctness. Gateway instance
  counts, gateway CPU/RSS, client resource usage, and TLS terminator resource
  snapshots help characterize the run.

The benchmark's application crypto fields describe the existing PQC
application workflow and are reported separately from TLS handshake time.
Use `tls_profile` and `mode` to distinguish the TLS transport from
application-layer protection.

## Compare baseline and improved application PQC

The baseline remains the default and keeps its existing packet format and
pure-Python implementation. The improved implementation is selected
explicitly and adds:

- an ML-DSA signature over a canonical digest of the metadata, timestamp,
  sequence number, nonce, and encrypted payload;
- a 128-bit random nonce, a strictly increasing per-sender sequence number,
  and a five-minute timestamp acceptance window;
- atomic replay checks shared by the gateway replicas through Redis; and
- native `liboqs` implementations of ML-KEM-768 and ML-DSA-65.

The pure-Python and native implementations use separate key pairs. Generate
the improved key material without replacing the baseline keys:

```powershell
docker compose --profile tools run --rm pqc-keygen
```

Compare the application-layer implementations over the same classical mTLS
transport. Keep the file types, sizes, and run count the same for both
commands. The report files are intentionally separate:

```powershell
docker compose down --remove-orphans
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml up --build -d redis gateway-1 gateway-2 gateway-3 tls-proxy
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml --profile tools run --rm benchmark python analysis/benchmark.py --network --mode application-pqc --implementation baseline --runs 5 --sizes 1 10 --filetypes txt csv json pdf --output benchmark-output/tls-application-pqc-baseline.json

docker compose -f docker-compose.yaml -f docker-compose.classical.yaml -f docker-compose.improved.yaml up --build -d redis gateway-1 gateway-2 gateway-3 tls-proxy
docker compose -f docker-compose.yaml -f docker-compose.classical.yaml -f docker-compose.improved.yaml --profile tools run --rm benchmark python analysis/benchmark.py --network --mode application-pqc --implementation improved --runs 5 --sizes 1 10 --filetypes txt csv json pdf --output benchmark-output/tls-application-pqc-improved.json
```

The improved Compose overlay configures the gateways and hospital/pharma
clients to require the improved packet format and native keys. Running the
benchmark in improved mode without that overlay (or without improved keys)
fails rather than silently selecting the baseline. The TLS dashboard loads
both reports from `benchmark-output`; the application dashboard compares
local crypto timing reports from `benchmark_results.json` and
`benchmark_results_improved.json`.

## Security and measurement scope

This is a local comparison/demo, not a production deployment. TLS terminates
at Nginx for client-facing requests and is re-established with mutual
authentication from Nginx to each gateway. Redis is demo-configured without
TLS or authentication. Production deployments still need Redis TLS/ACLs,
managed certificate and ticket-key rotation, and appropriate network
controls.

The TLS byte counters measure client-facing bytes observed by the benchmark,
not Ethernet/IP/TCP headers, retransmissions, or proxy-to-gateway traffic.
Backend TLS protects that hop but its wire bytes are not included in these
client-side counters. Resource readings are container/process snapshots and
can vary with host load. Compare repeated runs on the same host; a successful
short run is not a performance guarantee.

Stop the services when finished:

```powershell
docker compose down --remove-orphans
```
