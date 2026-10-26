import time
import json
import sys
import argparse
import math
import os
import statistics
import threading
import urllib.request
import hashlib
from pathlib import Path
from collections import Counter

import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from hospital.fakedatagenerator import generate_pharma_data
from analysis.tls_network_benchmark import create_client_context, perform_tls_post

with open(PROJECT_ROOT / "keys.json") as f:
    keys = json.load(f)

SERVER_EK = bytes.fromhex(keys["server_ek"])
SERVER_DK = bytes.fromhex(keys["server_dk"])
HOSPITAL_SK = bytes.fromhex(keys["hospital_sk"])
PHARMA_PK = bytes.fromhex(keys["pharma_pk"])


def derive_aes(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pharma-pqc-session"
    )
    return hkdf.derive(shared_secret)


def load_data(size_mb: int, filename: str = "fake_data.txt") -> bytes:
    data_path = PROJECT_ROOT / filename
    generate_pharma_data(filename=str(data_path), target_size_mb=size_mb)
    with open(data_path, "rb") as f:
        return f.read()


def run_full_cycle(data: bytes, include_network_payload: bool = False):
    t0 = time.perf_counter()
    ML_KEM_768.keygen()
    kem_keygen_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    ML_DSA_65.keygen()
    signature_keygen_time = time.perf_counter() - t0

    start_total = time.perf_counter()

    # ML-KEM encaps
    t0 = time.perf_counter()
    shared_secret_sender, kem_ct = ML_KEM_768.encaps(SERVER_EK)
    kem_encaps_time = time.perf_counter() - t0

    # ML-KEM decaps
    t0 = time.perf_counter()
    shared_secret_gateway = ML_KEM_768.decaps(SERVER_DK, kem_ct)
    kem_decaps_time = time.perf_counter() - t0

    if shared_secret_sender != shared_secret_gateway:
        return None

    aes_key = derive_aes(shared_secret_sender)

    # AES encrypt
    t0 = time.perf_counter()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    aes_ct = cipher.nonce + tag + ct # type: ignore
    aes_encrypt_time = time.perf_counter() - t0

    # ML-DSA sign
    t0 = time.perf_counter()
    sig = ML_DSA_65.sign(HOSPITAL_SK, aes_ct)
    sign_time = time.perf_counter() - t0

    # ML-DSA verify
    t0 = time.perf_counter()
    verified = ML_DSA_65.verify(PHARMA_PK, aes_ct, sig)
    verify_time = time.perf_counter() - t0

    if not verified:
        return None

    # AES decrypt
    t0 = time.perf_counter()
    nonce, tag, ciphertext = aes_ct[:16], aes_ct[16:32], aes_ct[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    decrypt_time = time.perf_counter() - t0

    total_time = time.perf_counter() - start_total

    result = {
        "data_size_mb": round(len(data) / (1024*1024), 2),
        "data_size_kb": round(len(data) / 1024, 1),
        "kem_keygen_time_ms": round(kem_keygen_time * 1000, 2),
        "kem_encaps_time_ms": round(kem_encaps_time * 1000, 2),
        "kem_decaps_time_ms": round(kem_decaps_time * 1000, 2),
        "signature_keygen_time_ms": round(signature_keygen_time * 1000, 2),
        "aes_encrypt_time_ms": round(aes_encrypt_time * 1000, 2),
        "sign_time_ms": round(sign_time * 1000, 2),
        "verify_time_ms": round(verify_time * 1000, 2),
        "decrypt_time_ms": round(decrypt_time * 1000, 2),
        "total_time_ms": round(total_time * 1000, 2),
        "total_application_processing_time_ms": round(
            (total_time + kem_keygen_time + signature_keygen_time) * 1000, 2
        ),
        "kem_ciphertext_bytes": len(kem_ct),
        "aes_ciphertext_bytes": len(aes_ct),
        "signature_bytes": len(sig),
        "verified": verified,
        "plaintext_match": plaintext == data
    }
    if include_network_payload:
        import hashlib

        result["_network_payload"] = json.dumps({
            "kem_ct": kem_ct.hex(),
            "ciphertext": aes_ct.hex(),
            "signature": sig.hex(),
            "metadata": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "original_payload_bytes": len(data),
            },
        }, separators=(",", ":")).encode("utf-8")
    return result


def benchmark_sizes(filetypes=("txt", "csv", "json", "pdf"), sizes=(1, 10, 50), runs=5):
    all_results = []

    for filetype in filetypes:
        for size in sizes:
            filename = f"fake_data_{size}mb.{filetype}"
            if filetype == "pdf":
                filename = f"fake_report_{size}mb.pdf"

            print(f"\n📦 Preparing dataset: {filename} ({size} MB)")
            data = load_data(size, filename=filename)

            valid_runs = []

            for i in range(runs):
                print(f"  ▶ Run {i+1}/{runs}")
                result = run_full_cycle(data)
                if result is not None:
                    result["filetype"] = filetype
                    result["filename"] = filename
                    valid_runs.append(result)

            if not valid_runs:
                continue

            avg = {}
            for key in valid_runs[0]:
                if key in ["verified", "plaintext_match"]:
                    avg[key] = all(r[key] for r in valid_runs)
                elif isinstance(valid_runs[0][key], (int, float)):
                    avg[key] = round(sum(r[key] for r in valid_runs) / len(valid_runs), 2)
                else:
                    avg[key] = valid_runs[0][key]

            all_results.append(avg)

    return all_results


def percentile_summary(values):
    if not values:
        return {"median": None, "p95": None, "min": None, "max": None}
    ordered = sorted(values)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "median": round(statistics.median(ordered), 3),
        "p95": round(ordered[p95_index], 3),
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
    }


class ResourceMonitor:
    def __init__(self, sample_interval_seconds=0.05):
        self._process = psutil.Process()
        self._sample_interval = sample_interval_seconds
        self._stop = threading.Event()
        self._peak_rss = self._process.memory_info().rss
        self._thread = threading.Thread(target=self._sample_memory, daemon=True)

    def _sample_memory(self):
        while not self._stop.wait(self._sample_interval):
            try:
                self._peak_rss = max(
                    self._peak_rss,
                    self._process.memory_info().rss,
                )
            except psutil.Error:
                return

    def __enter__(self):
        self._start_wall = time.perf_counter()
        self._start_cpu = self._process.cpu_times()
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop.set()
        self._thread.join()
        self._peak_rss = max(self._peak_rss, self._process.memory_info().rss)
        self._end_wall = time.perf_counter()
        self._end_cpu = self._process.cpu_times()

    def results(self):
        cpu_ms = (
            (self._end_cpu.user + self._end_cpu.system)
            - (self._start_cpu.user + self._start_cpu.system)
        ) * 1000
        wall_ms = (self._end_wall - self._start_wall) * 1000
        return {
            "client_cpu_time_ms": round(cpu_ms, 3),
            "client_cpu_percent": round(cpu_ms / wall_ms * 100, 2) if wall_ms else 0,
            "client_peak_memory_bytes": self._peak_rss,
            "client_peak_memory_kb": round(self._peak_rss / 1024, 1),
            "client_memory_rss_bytes": self._process.memory_info().rss,
        }


def _network_request(
    *,
    mode,
    data,
    app_cycle,
    host,
    port,
    server_name,
    context,
    session=None,
):
    if mode == "application-pqc":
        payload = app_cycle["_network_payload"]
        path = "/benchmark/pqc"
    else:
        payload = data
        path = "/benchmark/echo"

    result = perform_tls_post(
        host=host,
        port=port,
        server_name=server_name,
        path=path,
        payload=payload,
        context=context,
        session=session,
    )
    response = result["response_json"]
    if mode == "application-pqc":
        result["correctness"] = (
            response.get("verified") is True
            and response.get("plaintext_match") is True
            and response.get("plaintext_bytes") == len(data)
        )
        result["receiver_decrypt_time_ms"] = response.get("receiver_decrypt_time_ms")
        result["receiver_verify_time_ms"] = response.get("receiver_verify_time_ms")
    else:
        import hashlib

        result["correctness"] = (
            response.get("bytes_received") == len(data)
            and response.get("sha256") == hashlib.sha256(data).hexdigest()
        )
    result["network_payload_bytes"] = len(payload)
    return result


def benchmark_network_dataset(
    data,
    *,
    filetype,
    filename,
    mode,
    runs,
    host,
    port,
    server_name,
    ca_file,
    cert_file,
    key_file,
):
    required_profile = "pq-hybrid-tls" if mode == "pq-hybrid-tls" else "classical-mtls"
    configured_profile = os.environ.get("TLS_PROFILE", required_profile)
    if configured_profile != required_profile:
        raise RuntimeError(
            f"Mode {mode!r} requires TLS_PROFILE={required_profile!r}; "
            f"the container has {configured_profile!r}."
        )

    keygen_fields = []
    crypto_runs = []
    fresh_runs = []
    resumed_runs = []
    errors = Counter()
    instance_counts = Counter()
    handshake_bytes = {
        "fresh": {"sent": 0, "received": 0},
        "resumed": {"sent": 0, "received": 0},
    }
    application_phase_bytes = {"sent": 0, "received": 0}
    wire_bytes = {"sent": 0, "received": 0}
    network_payload_bytes_sent = 0
    original_payload_bytes_transferred = 0
    http_payload_bytes_received = 0
    receiver_decrypt_times = []
    receiver_verify_times = []
    gateway_cpu_times = []
    gateway_memory_samples = []
    request_rtt_by_kind = {"fresh": [], "resumed": []}
    throughput_by_kind = {"fresh": [], "resumed": []}
    wire_throughput_by_kind = {"fresh": [], "resumed": []}
    tcp_connect_times = []
    tls_versions = Counter()
    ciphers = Counter()
    correctness = []
    successful_requests = 0
    failed_requests = 0
    resumption_successes = 0
    resumption_attempts = 0
    fresh_handshake_attempts = 0
    proxy_metrics_url = os.environ.get("TLS_PROXY_METRICS_URL")
    proxy_metrics_before = _read_proxy_metrics(proxy_metrics_url)

    def record_wire(result):
        nonlocal network_payload_bytes_sent
        nonlocal original_payload_bytes_transferred
        phase = "resumed" if result["session_reused"] else "fresh"
        handshake_bytes[phase]["sent"] += result["handshake_bytes_sent"]
        handshake_bytes[phase]["received"] += result["handshake_bytes_received"]
        application_phase_bytes["sent"] += result["application_bytes_sent"]
        application_phase_bytes["received"] += result["application_bytes_received"]
        wire_bytes["sent"] += (
            result["handshake_bytes_sent"] + result["application_bytes_sent"]
        )
        wire_bytes["received"] += (
            result["handshake_bytes_received"] + result["application_bytes_received"]
        )
        network_payload_bytes_sent += result["network_payload_bytes"]
        original_payload_bytes_transferred += len(data)

    def record_server_metrics(result):
        instance_counts[result["gateway_instance"]] += 1
        tcp_connect_times.append(result["tcp_connect_ms"])
        tls_versions[result["tls_version"]] += 1
        if result["cipher"]:
            ciphers[result["cipher"]] += 1
        gateway_cpu_times.append(result["gateway_cpu_time_ms"])
        gateway_memory_samples.append(result["gateway_memory_rss_bytes"])
        if result.get("receiver_decrypt_time_ms") is not None:
            receiver_decrypt_times.append(result["receiver_decrypt_time_ms"])
            receiver_verify_times.append(result["receiver_verify_time_ms"])

    with ResourceMonitor() as resource_monitor:
        resume_context = create_client_context(ca_file, cert_file, key_file)
        resume_seed = None
        for run_index in range(runs):
            app_cycle = run_full_cycle(
                data,
                include_network_payload=(mode == "application-pqc"),
            )
            if app_cycle is None:
                errors["application_crypto_failure"] += 1
                failed_requests += 2
                continue
            crypto_runs.append(app_cycle)
            keygen_fields.append({
                "kem_keygen_time_ms": app_cycle["kem_keygen_time_ms"],
                "signature_keygen_time_ms": app_cycle["signature_keygen_time_ms"],
            })

            fresh_context = (
                resume_context
                if run_index == 0
                else create_client_context(ca_file, cert_file, key_file)
            )
            fresh = None
            fresh_handshake_attempts += 1
            try:
                fresh = _network_request(
                    mode=mode,
                    data=data,
                    app_cycle=app_cycle,
                    host=host,
                    port=port,
                    server_name=server_name,
                    context=fresh_context,
                )
                fresh_runs.append(fresh)
                record_wire(fresh)
                http_payload_bytes_received += fresh["http_response_bytes"]
                if fresh["status_code"] >= 200 and fresh["status_code"] < 300:
                    successful_requests += 1
                    correctness.append(fresh["correctness"])
                    request_rtt_by_kind["fresh"].append(fresh["request_rtt_ms"])
                    throughput_by_kind["fresh"].append(
                        len(data) * 8 / fresh["request_rtt_ms"] / 1000
                    )
                    wire_throughput_by_kind["fresh"].append(
                        (
                            fresh["application_bytes_sent"]
                            + fresh["application_bytes_received"]
                        )
                        * 8
                        / fresh["request_rtt_ms"]
                        / 1000
                    )
                    record_server_metrics(fresh)
                else:
                    failed_requests += 1
                    errors[f"fresh_http_{fresh['status_code']}"] += 1
            except (OSError, ssl.SSLError, ValueError, RuntimeError) as exc:
                failed_requests += 1
                errors[f"fresh_{type(exc).__name__}"] += 1

            if run_index == 0 and fresh is not None:
                resume_seed = fresh.get("session")
            if resume_seed is None:
                failed_requests += 1
                errors["resumption_session_unavailable"] += 1
                continue

            resumption_attempts += 1
            try:
                resumed = _network_request(
                    mode=mode,
                    data=data,
                    app_cycle=app_cycle,
                    host=host,
                    port=port,
                    server_name=server_name,
                    context=resume_context,
                    session=resume_seed,
                )
                resumed_runs.append(resumed)
                record_wire(resumed)
                http_payload_bytes_received += resumed["http_response_bytes"]
                if resumed["session_reused"]:
                    resumption_successes += 1
                    request_rtt_by_kind["resumed"].append(resumed["request_rtt_ms"])
                    throughput_by_kind["resumed"].append(
                        len(data) * 8 / resumed["request_rtt_ms"] / 1000
                    )
                    wire_throughput_by_kind["resumed"].append(
                        (
                            resumed["application_bytes_sent"]
                            + resumed["application_bytes_received"]
                        )
                        * 8
                        / resumed["request_rtt_ms"]
                        / 1000
                    )
                else:
                    errors["resumption_not_negotiated"] += 1
                if resumed["status_code"] >= 200 and resumed["status_code"] < 300:
                    successful_requests += 1
                    correctness.append(resumed["correctness"])
                    record_server_metrics(resumed)
                    resume_seed = resumed["session"]
                else:
                    failed_requests += 1
                    errors[f"resumed_http_{resumed['status_code']}"] += 1
            except (OSError, ssl.SSLError, ValueError, RuntimeError) as exc:
                failed_requests += 1
                errors[f"resumed_{type(exc).__name__}"] += 1

    resource_values = resource_monitor.results()
    proxy_metrics_after = _read_proxy_metrics(proxy_metrics_url)
    if not crypto_runs:
        raise RuntimeError("No cryptographic benchmark iteration completed successfully.")

    def mean(field):
        values = [run[field] for run in crypto_runs if isinstance(run.get(field), (int, float))]
        return round(statistics.mean(values), 3) if values else None

    request_rtts = request_rtt_by_kind["fresh"] + request_rtt_by_kind["resumed"]
    throughputs = throughput_by_kind["fresh"] + throughput_by_kind["resumed"]
    wire_throughputs = (
        wire_throughput_by_kind["fresh"] + wire_throughput_by_kind["resumed"]
    )
    original_bytes_for_successful_requests = original_payload_bytes_transferred
    total_wire = wire_bytes["sent"] + wire_bytes["received"]
    overhead_bytes = total_wire - original_bytes_for_successful_requests
    total_attempts = successful_requests + failed_requests
    result = {
        "schema_version": 2,
        "mode": mode,
        "tls_profile": configured_profile,
        "filetype": filetype,
        "filename": filename,
        "original_payload_sha256": hashlib.sha256(data).hexdigest(),
        "data_size_mb": round(len(data) / (1024 * 1024), 3),
        "data_size_kb": round(len(data) / 1024, 1),
        "runs": runs,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "success_rate_percent": round(
            successful_requests / total_attempts * 100, 2
        ) if total_attempts else 0,
        "failure_rate_percent": round(
            failed_requests / total_attempts * 100, 2
        ) if total_attempts else 0,
        "tls_resumption_attempts": resumption_attempts,
        "tls_resumption_successes": resumption_successes,
        "tls_resumption_success_rate_percent": round(
            resumption_successes / resumption_attempts * 100, 2
        ) if resumption_attempts else 0,
        "tls_handshake_successes": len(fresh_runs) + len(resumed_runs),
        "tls_handshake_failures": max(
            0,
            fresh_handshake_attempts + resumption_attempts
            - len(fresh_runs)
            - len(resumed_runs),
        ),
        "tls_handshake_success_rate_percent": round(
            (len(fresh_runs) + len(resumed_runs))
            / (fresh_handshake_attempts + resumption_attempts)
            * 100,
            2,
        ) if fresh_handshake_attempts + resumption_attempts else 0,
        "tls_fresh_handshake_latency_ms": percentile_summary(
            [run["handshake_ms"] for run in fresh_runs]
        ),
        "tls_resumed_handshake_latency_ms": percentile_summary(
            [run["handshake_ms"] for run in resumed_runs if run["session_reused"]]
        ),
        "tcp_connect_latency_ms": percentile_summary(tcp_connect_times),
        "request_rtt_ms": percentile_summary(request_rtts),
        "request_rtt_by_handshake_ms": {
            name: percentile_summary(values)
            for name, values in request_rtt_by_kind.items()
        },
        "payload_throughput_mbps": percentile_summary(throughputs),
        "payload_throughput_by_handshake_mbps": {
            name: percentile_summary(values)
            for name, values in throughput_by_kind.items()
        },
        "wire_throughput_mbps": percentile_summary(wire_throughputs),
        "tls_handshake_bytes_sent": {
            name: counts["sent"] for name, counts in handshake_bytes.items()
        },
        "tls_handshake_bytes_received": {
            name: counts["received"] for name, counts in handshake_bytes.items()
        },
        "tls_application_phase_bytes_sent": application_phase_bytes["sent"],
        "tls_application_phase_bytes_received": application_phase_bytes["received"],
        "application_payload_bytes_sent": network_payload_bytes_sent,
        "original_payload_bytes_sent": original_bytes_for_successful_requests,
        "application_layer_overhead_bytes": (
            network_payload_bytes_sent - original_bytes_for_successful_requests
        ),
        "http_response_bytes_received": http_payload_bytes_received,
        "total_bytes_transferred": {
            "sent": wire_bytes["sent"],
            "received": wire_bytes["received"],
            "total": total_wire,
        },
        "communication_overhead_bytes": overhead_bytes,
        "communication_overhead_kb": round(overhead_bytes / 1024, 3),
        "communication_overhead_percent": round(
            overhead_bytes / original_bytes_for_successful_requests * 100, 3
        ) if original_bytes_for_successful_requests else None,
        "kem_keygen_time_ms": mean("kem_keygen_time_ms"),
        "signature_keygen_time_ms": mean("signature_keygen_time_ms"),
        "kem_encaps_time_ms": mean("kem_encaps_time_ms"),
        "kem_decaps_time_ms": mean("kem_decaps_time_ms"),
        "aes_encrypt_time_ms": mean("aes_encrypt_time_ms"),
        "sign_time_ms": mean("sign_time_ms"),
        "verify_time_ms": mean("verify_time_ms"),
        "decrypt_time_ms": mean("decrypt_time_ms"),
        "total_time_ms": mean("total_time_ms"),
        "total_application_processing_time_ms": mean(
            "total_application_processing_time_ms"
        ),
        "receiver_decrypt_time_ms": percentile_summary(receiver_decrypt_times),
        "receiver_verify_time_ms": percentile_summary(receiver_verify_times),
        "kem_ciphertext_bytes": int(mean("kem_ciphertext_bytes") or 0),
        "aes_ciphertext_bytes": int(mean("aes_ciphertext_bytes") or 0),
        "signature_bytes": int(mean("signature_bytes") or 0),
        "cryptographic_timing_ms": {
            field: percentile_summary(
                [run[field] for run in crypto_runs]
            )
            for field in (
                "kem_keygen_time_ms",
                "kem_encaps_time_ms",
                "kem_decaps_time_ms",
                "signature_keygen_time_ms",
                "aes_encrypt_time_ms",
                "sign_time_ms",
                "verify_time_ms",
                "decrypt_time_ms",
                "total_time_ms",
                "total_application_processing_time_ms",
            )
        },
        "verified": all(run["verified"] for run in crypto_runs)
        and all(value is True for value in correctness),
        "plaintext_match": all(run["plaintext_match"] for run in crypto_runs)
        and all(value is True for value in correctness),
        "gateway_instance_counts": dict(instance_counts),
        "tls_versions": dict(tls_versions),
        "tls_ciphers": dict(ciphers),
        "gateway_cpu_time_ms": percentile_summary(gateway_cpu_times),
        "gateway_memory_rss_bytes": percentile_summary(gateway_memory_samples),
        "client_resources": resource_values,
        "tls_terminator_resources": _resource_delta(
            proxy_metrics_before,
            proxy_metrics_after,
        ),
        "errors": dict(errors),
    }

    return result


def _read_proxy_metrics(url):
    if not url:
        return None
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read())


def _resource_delta(before, after):
    if before is None or after is None:
        return None
    return {
        "cpu_time_ms": round(after["cpu_time_ms"] - before["cpu_time_ms"], 3),
        "memory_rss_bytes": after["memory_rss_bytes"],
        "peak_memory_rss_bytes": after["peak_memory_rss_bytes"],
    }


def benchmark_network(
    *,
    mode,
    filetypes,
    sizes,
    runs,
    output_path,
    host,
    port,
    server_name,
    ca_file,
    cert_file,
    key_file,
):
    results = []
    dataset_dir = output_path.parent / "datasets"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    for filetype in filetypes:
        for size in sizes:
            filename = f"fake_data_{size}mb.{filetype}"
            if filetype == "pdf":
                filename = f"fake_report_{size}mb.pdf"
            print(f"\nPreparing {filename} ({size} MB) for {mode}")
            dataset_path = dataset_dir / filename
            if dataset_path.exists():
                data = dataset_path.read_bytes()
            else:
                generate_pharma_data(
                    filename=str(dataset_path),
                    target_size_mb=size,
                )
                data = dataset_path.read_bytes()
            result = benchmark_network_dataset(
                data,
                filetype=filetype,
                filename=filename,
                mode=mode,
                runs=runs,
                host=host,
                port=port,
                server_name=server_name,
                ca_file=ca_file,
                cert_file=cert_file,
                key_file=key_file,
            )
            results.append(result)
            print(json.dumps(result, indent=2))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as result_file:
        json.dump(results, result_file, indent=2)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC and TLS network benchmark")
    parser.add_argument("--network", action="store_true", help="Measure real TLS network traffic.")
    parser.add_argument(
        "--mode",
        choices=("classical-mtls", "pq-hybrid-tls", "application-pqc"),
        default="pq-hybrid-tls",
    )
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--sizes", type=int, nargs="+", default=(1, 10))
    parser.add_argument(
        "--filetypes",
        nargs="+",
        default=("txt", "csv", "json", "pdf"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Result path; network mode defaults to benchmark-output/tls-<mode>.json.",
    )
    args = parser.parse_args()

    if args.runs < 1 or any(size < 1 for size in args.sizes):
        parser.error("--runs and each --sizes value must be positive.")

    if args.network:
        tls_files = {
            "CA certificate": os.environ.get("GATEWAY_CA_FILE"),
            "client certificate": os.environ.get("GATEWAY_CLIENT_CERT_FILE"),
            "client private key": os.environ.get("GATEWAY_CLIENT_KEY_FILE"),
        }
        missing = [name for name, path in tls_files.items() if not path]
        if missing:
            parser.error("TLS network mode requires " + ", ".join(missing))
        output = args.output or (
            PROJECT_ROOT / "benchmark-output" / f"tls-{args.mode}.json"
        )
        benchmark_network(
            mode=args.mode,
            filetypes=args.filetypes,
            sizes=args.sizes,
            runs=args.runs,
            output_path=output,
            host=os.environ.get("GATEWAY_HOST", "127.0.0.1"),
            port=int(os.environ.get("GATEWAY_PORT", "5001")),
            server_name=os.environ.get("GATEWAY_TLS_SERVER_NAME", "gateway"),
            ca_file=tls_files["CA certificate"],
            cert_file=tls_files["client certificate"],
            key_file=tls_files["client private key"],
        )
    else:
        results = benchmark_sizes(
            filetypes=tuple(args.filetypes),
            sizes=tuple(args.sizes),
            runs=args.runs,
        )
        print("=== PQC Pharmacovigilance Benchmark Results ===")
        for result in results:
            print(json.dumps(result, indent=2))
        output = args.output or (PROJECT_ROOT / "benchmark_results.json")
        with open(output, "w", encoding="utf-8") as result_file:
            json.dump(results, result_file, indent=2)
        print(f"\nSaved results to {output}")