from flask import Flask, request, jsonify, render_template, redirect
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import json
import os
import ssl
import hashlib
import time
import psutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.dashboard_data import load_tls_benchmark_reports
from gateway.storage import create_packet_store
from crypto_backend import IMPROVED, decapsulate, key_fields, verify
from packet_auth import (
    MAX_CLOCK_SKEW_SECONDS,
    signature_digest,
    timestamp_is_fresh,
)

app = Flask(__name__, template_folder="templates")
packet_store = create_packet_store()

with open("keys.json") as f:
    keys = json.load(f)
PQC_IMPLEMENTATION = os.environ.get("PQC_IMPLEMENTATION", "baseline")
SERVER_EK, SERVER_DK, HOSPITAL_SK, PHARMA_PK = key_fields(
    keys,
    PQC_IMPLEMENTATION,
)


def derive_aes(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pharma-pqc-session",
    ).derive(shared_secret)


def add_resource_headers(response, process, started_at, cpu_started):
    cpu_now = process.cpu_times()
    response.headers["X-Gateway-CPU-Time-Ms"] = str(
        round(((cpu_now.user + cpu_now.system) - cpu_started) * 1000, 3)
    )
    response.headers["X-Gateway-Memory-RSS-Bytes"] = str(
        process.memory_info().rss
    )
    response.headers["X-Gateway-Instance"] = os.environ.get("HOSTNAME", "local")
    response.headers["X-Gateway-Processing-Time-Ms"] = str(
        round((time.perf_counter() - started_at) * 1000, 3)
    )
    return response


def verify_improved_packet(packet):
    if PQC_IMPLEMENTATION != IMPROVED:
        return False, "Improved packets require PQC_IMPLEMENTATION=improved."

    try:
        digest = signature_digest(packet)
        signature = bytes.fromhex(packet["signature"])
        metadata = packet["metadata"]
    except (KeyError, TypeError, ValueError) as exc:
        return False, str(exc)

    if not isinstance(metadata.get("source"), str) or not metadata["source"]:
        return False, "Authenticated packet metadata must include a source."
    if not timestamp_is_fresh(packet["timestamp"]):
        return False, "Packet timestamp is outside the accepted time window."
    if not verify(PQC_IMPLEMENTATION, PHARMA_PK, digest, signature):
        return False, "Invalid ML-DSA signature."
    return True, None


def accept_improved_packet(packet):
    accepted, error = verify_improved_packet(packet)
    if not accepted:
        return None, (error or "Invalid authenticated packet.", 400)

    try:
        nonce = packet["nonce"]
        source = packet["metadata"]["source"]
        timestamp = packet["timestamp"]
        sequence = packet["sequence"]
        ciphertext = bytes.fromhex(packet["ciphertext"])
        kem_ciphertext = bytes.fromhex(packet["kem_ct"])
    except (KeyError, TypeError, ValueError) as exc:
        return None, (str(exc), 400)

    shared_secret = decapsulate(PQC_IMPLEMENTATION, SERVER_DK, kem_ciphertext)
    replay_result = packet_store.accept_packet(
        source=source,
        sequence=sequence,
        nonce=nonce,
        expires_at=timestamp + 2 * MAX_CLOCK_SKEW_SECONDS,
    )
    if replay_result != "accepted":
        return None, (f"Packet rejected: {replay_result}.", 409)
    return shared_secret, None


@app.route("/")
def home():
    return redirect("/dashboard")


@app.route("/send", methods=["POST"])
def receive():
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    metadata = data.get("metadata", {})
    source = metadata.get("source", "unknown") if isinstance(metadata, dict) else "unknown"
    print("\n📩 [GATEWAY] Received packet from", source)

    if data.get("protocol_version") == 2:
        shared_secret, error = accept_improved_packet(data)
        if error:
            message, status = error
            return jsonify({"error": message}), status
    elif PQC_IMPLEMENTATION == IMPROVED:
        return jsonify({"error": "The improved gateway requires authenticated packet version 2."}), 400
    elif "kem_ct" in data:
        try:
            kem_ct = bytes.fromhex(data["kem_ct"])
            shared_secret = decapsulate(PQC_IMPLEMENTATION, SERVER_DK, kem_ct)
        except (TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
    else:
        shared_secret = None

    packet = data.copy()
    if shared_secret is not None:
        packet["session_key"] = shared_secret.hex()
        packet["status"] = "received"

    log_id = packet_store.append(packet)
    return jsonify({"status": "received", "log_id": log_id})


@app.route("/logs", methods=["GET"])
def get_logs():
    response = jsonify(packet_store.get_all())
    response.headers["X-Gateway-Instance"] = os.environ.get("HOSTNAME", "local")
    return response


@app.route("/health")
def health():
    if not packet_store.ping():
        return jsonify({"status": "unavailable"}), 503
    return jsonify({"status": "ok"})


@app.route("/benchmark/echo", methods=["POST"])
def benchmark_echo():
    from hashlib import sha256

    process = psutil.Process()
    started_at = time.perf_counter()
    cpu_times = process.cpu_times()
    cpu_started = cpu_times.user + cpu_times.system
    payload = request.get_data(cache=False)
    response = jsonify({
        "bytes_received": len(payload),
        "sha256": sha256(payload).hexdigest(),
    })
    return add_resource_headers(response, process, started_at, cpu_started)


@app.route("/benchmark/pqc", methods=["POST"])
def benchmark_pqc():
    process = psutil.Process()
    started_at = time.perf_counter()
    cpu_times = process.cpu_times()
    cpu_started = cpu_times.user + cpu_times.system
    try:
        envelope = request.get_json()
        if not isinstance(envelope, dict):
            raise ValueError("Expected a JSON PQC envelope.")

        verify_started = time.perf_counter()
        if envelope.get("protocol_version") == 2:
            accepted, error = verify_improved_packet(envelope)
            if not accepted:
                return jsonify({"error": error}), 400
        elif PQC_IMPLEMENTATION == IMPROVED:
            return jsonify({"error": "The improved gateway requires authenticated packet version 2."}), 400
        else:
            signature = bytes.fromhex(envelope["signature"])
            aes_ct = bytes.fromhex(envelope["ciphertext"])
            if not verify(PQC_IMPLEMENTATION, PHARMA_PK, aes_ct, signature):
                return jsonify({"error": "Invalid ML-DSA signature"}), 400
        verify_ms = (time.perf_counter() - verify_started) * 1000

        kem_ct = bytes.fromhex(envelope["kem_ct"])
        aes_ct = bytes.fromhex(envelope["ciphertext"])
        expected_sha256 = envelope["metadata"]["sha256"]
        shared_secret = decapsulate(PQC_IMPLEMENTATION, SERVER_DK, kem_ct)
        if envelope.get("protocol_version") == 2:
            replay_result = packet_store.accept_packet(
                source=envelope["metadata"]["source"],
                sequence=envelope["sequence"],
                nonce=envelope["nonce"],
                expires_at=(
                    envelope["timestamp"] + 2 * MAX_CLOCK_SKEW_SECONDS
                ),
            )
            if replay_result != "accepted":
                return jsonify({"error": f"Packet rejected: {replay_result}"}), 409

        decrypt_started = time.perf_counter()
        cipher = AES.new(derive_aes(shared_secret), AES.MODE_GCM, nonce=aes_ct[:16])
        plaintext = cipher.decrypt_and_verify(aes_ct[32:], aes_ct[16:32])
        decrypt_ms = (time.perf_counter() - decrypt_started) * 1000
        response = jsonify({
            "bytes_received": request.content_length or 0,
            "plaintext_bytes": len(plaintext),
            "plaintext_match": hashlib.sha256(plaintext).hexdigest() == expected_sha256,
            "verified": True,
            "receiver_verify_time_ms": round(verify_ms, 3),
            "receiver_decrypt_time_ms": round(decrypt_ms, 3),
        })
        return add_resource_headers(response, process, started_at, cpu_started)
    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/dashboard")
def dashboard():
    benchmark_results = []
    benchmark_path = PROJECT_ROOT / "benchmark_results.json"
    if benchmark_path.exists():
        with benchmark_path.open(encoding="utf-8") as benchmark_file:
            benchmark_results = json.load(benchmark_file)

    improved_results = []
    improved_path = PROJECT_ROOT / "benchmark_results_improved.json"
    if improved_path.exists():
        with improved_path.open(encoding="utf-8") as benchmark_file:
            improved_results = json.load(benchmark_file)

    return render_template(
        "dashboard.html",
        logs=packet_store.get_all(),
        benchmark_results=benchmark_results,
        improved_benchmark_results=improved_results,
    )


@app.route("/tls-dashboard")
def tls_dashboard():
    reports = load_tls_benchmark_reports(PROJECT_ROOT / "benchmark-output")
    benchmark_path = PROJECT_ROOT / "benchmark_results.json"
    benchmark_results = []
    if benchmark_path.exists():
        with benchmark_path.open(encoding="utf-8") as benchmark_file:
            benchmark_results = json.load(benchmark_file)

    return render_template(
        "tls_dashboard.html",
        reports=reports,
        benchmark_results=benchmark_results,
    )


if __name__ == "__main__":
    tls_files = {
        "certificate": os.environ.get("GATEWAY_TLS_CERT_FILE"),
        "private key": os.environ.get("GATEWAY_TLS_KEY_FILE"),
        "client CA": os.environ.get("GATEWAY_TLS_CA_FILE"),
    }
    configured = [path is not None for path in tls_files.values()]
    if any(configured) and not all(configured):
        missing = [name for name, path in tls_files.items() if path is None]
        raise RuntimeError(
            "Incomplete gateway TLS configuration; missing " + ", ".join(missing)
        )

    tls_context = None
    if all(configured):
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_cert_chain(
            certfile=tls_files["certificate"],
            keyfile=tls_files["private key"],
        )
        tls_context.load_verify_locations(cafile=tls_files["client CA"])
        tls_context.verify_mode = ssl.CERT_REQUIRED
        scheme = "https"
    else:
        scheme = "http"

    port = int(os.environ.get("PORT", "5001"))
    print(f"🚀 Gateway running on {scheme}://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)