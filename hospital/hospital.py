import requests
import os
import json
import sys
import mimetypes
from pathlib import Path
from datetime import datetime, timezone
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tls_client import configure_gateway_session
from crypto_backend import BASELINE, encapsulate, key_fields, sign
from packet_auth import packet_auth_fields, signature_digest

# ================== CONFIG ==================
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:5001")
PQC_IMPLEMENTATION = os.environ.get("PQC_IMPLEMENTATION", BASELINE)
KEYS_FILE = "keys.json"
# ============================================

with open(KEYS_FILE) as f:
    keys = json.load(f)

SERVER_EK, SERVER_DK, HOSPITAL_SK, PHARMA_PK = key_fields(keys, PQC_IMPLEMENTATION)


def derive_aes(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pharma-pqc-session"
    )
    return hkdf.derive(shared_secret)


def load_file_with_metadata(file_path: str):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    filename = os.path.basename(file_path)
    filetype = os.path.splitext(filename)[1].lstrip(".").lower()
    mime_type, _ = mimetypes.guess_type(file_path)
    mime_type = mime_type or "application/octet-stream"

    metadata = {
        "filename": filename,
        "filetype": filetype,
        "mime_type": mime_type,
        "data_size_kb": round(len(data) / 1024, 1)
    }

    return data, metadata


def main():
    if len(sys.argv) < 2:
        print("Usage: python hospital/hospital.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    # === Step 1: Load file + metadata ===
    file_data, file_meta = load_file_with_metadata(file_path)
    print(f"📄 Loaded file: {file_meta['filename']}")
    print(f"   Type: {file_meta['filetype'] or 'unknown'}")
    print(f"   MIME: {file_meta['mime_type']}")
    print(f"   Size: {file_meta['data_size_kb']} KB")

    # === Step 2: ML-KEM handshake with Gateway ===
    shared_secret, kem_ct = encapsulate(PQC_IMPLEMENTATION, SERVER_EK)
    print("✅ ML-KEM-768 handshake completed")

    # === Step 3: Derive AES-256 key using HKDF ===
    aes_key = derive_aes(shared_secret)

    # === Step 4: AES-GCM encrypt file bytes ===
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    aes_ct = cipher.nonce + tag + ciphertext #type: ignore

    print("🔐 AES-256-GCM encryption complete")

    # === Step 5: ML-DSA sign encrypted payload ===
    payload = {
        "kem_ct": kem_ct.hex(),
        "ciphertext": aes_ct.hex(),
        "metadata": {
            "source": "hospital_A",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **file_meta
        }
    }
    if PQC_IMPLEMENTATION == BASELINE:
        payload["signature"] = sign(
            PQC_IMPLEMENTATION,
            HOSPITAL_SK,
            aes_ct,
        ).hex()
    else:
        payload.update(packet_auth_fields())
        payload["signature"] = sign(
            PQC_IMPLEMENTATION,
            HOSPITAL_SK,
            signature_digest(payload),
        ).hex()
    print("✍️ ML-DSA-65 signature generated")

    # === Step 6: Send to Gateway ===
    session = requests.Session()
    configure_gateway_session(session, GATEWAY_URL)
    response = session.post(f"{GATEWAY_URL}/send", json=payload, timeout=30)
    response.raise_for_status()
    print("🚀 Sent encrypted & signed payload to Gateway")
    print("Response:", response.json())


if __name__ == "__main__":
    main()