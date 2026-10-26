from flask import Flask, request, jsonify, render_template, redirect
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
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

app = Flask(__name__, template_folder="templates")
packet_store = create_packet_store()

with open("keys.json") as f:
    keys = json.load(f)
SERVER_DK = bytes.fromhex(keys["server_dk"])
PHARMA_PK = bytes.fromhex(keys["pharma_pk"])


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

    if "kem_ct" in data:
        kem_ct = bytes.fromhex(data["kem_ct"])
        shared_secret = ML_KEM_768.decaps(SERVER_DK, kem_ct)
        print("✅ ML-KEM-768 decapsulation successful")

        packet = data.copy()
        packet["session_key"] = shared_secret.hex()
        packet["status"] = "received"
    else:
        packet = data.copy()

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

        kem_ct = bytes.fromhex(envelope["kem_ct"])
        aes_ct = bytes.fromhex(envelope["ciphertext"])
        signature = bytes.fromhex(envelope["signature"])
        expected_sha256 = envelope["metadata"]["sha256"]
        shared_secret = ML_KEM_768.decaps(SERVER_DK, kem_ct)

        verify_started = time.perf_counter()
        verified = ML_DSA_65.verify(PHARMA_PK, aes_ct, signature)
        verify_ms = (time.perf_counter() - verify_started) * 1000
        if not verified:
            return jsonify({"error": "Invalid ML-DSA signature"}), 400

        decrypt_started = time.perf_counter()
        cipher = AES.new(derive_aes(shared_secret), AES.MODE_GCM, nonce=aes_ct[:16])
        plaintext = cipher.decrypt_and_verify(aes_ct[32:], aes_ct[16:32])
        decrypt_ms = (time.perf_counter() - decrypt_started) * 1000
        response = jsonify({
            "bytes_received": request.content_length or 0,
            "plaintext_bytes": len(plaintext),
            "plaintext_match": hashlib.sha256(plaintext).hexdigest() == expected_sha256,
            "verified": verified,
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
        with benchmark_path.open(encoding="utf-8") as f:
            benchmark_results = json.load(f)

    return render_template(
        "dashboard.html",
        logs=packet_store.get_all(),
        benchmark_results=benchmark_results,
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