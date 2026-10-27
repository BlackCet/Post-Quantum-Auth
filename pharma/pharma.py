import requests
import json
import os
import sys
from pathlib import Path
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tls_client import configure_gateway_session
from crypto_backend import BASELINE, IMPROVED, key_fields, verify
from packet_auth import signature_digest

# ================== CONFIG ==================
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:5001")
PQC_IMPLEMENTATION = os.environ.get("PQC_IMPLEMENTATION", BASELINE)
KEYS_FILE = "keys.json"
OUTPUT_DIR = "received_files"
# ============================================

with open(KEYS_FILE) as f:
    keys = json.load(f)

SERVER_EK, SERVER_DK, HOSPITAL_SK, PHARMA_PK = key_fields(
    keys,
    PQC_IMPLEMENTATION,
)


def derive_aes(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pharma-pqc-session"
    )
    return hkdf.derive(shared_secret)


def preview_text_if_possible(filetype: str, plaintext: bytes):
    if filetype in ["txt", "csv", "json"]:
        try:
            print("\n📖 Preview of decrypted content:")
            print(plaintext.decode("utf-8", errors="replace")[:500] + "...")
        except Exception:
            print("Could not decode text preview.")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    session = requests.Session()
    configure_gateway_session(session, GATEWAY_URL)
    response = session.get(f"{GATEWAY_URL}/logs", timeout=30)
    response.raise_for_status()
    data = response.json()
    if not data:
        print("No packets yet")
        return

    packet = data[-1]
    print("📥 Received latest packet")

    metadata = packet.get("metadata", {})
    filename = metadata.get("filename", "received_file.bin")
    filetype = metadata.get("filetype", "")
    source = metadata.get("source", "unknown")

    # === Step 1: Verify ML-DSA signature ===
    ct = bytes.fromhex(packet["ciphertext"])
    sig = bytes.fromhex(packet["signature"])

    if PQC_IMPLEMENTATION == IMPROVED:
        try:
            signed_message = signature_digest(packet)
        except (KeyError, TypeError, ValueError) as exc:
            print(f"❌ Invalid authenticated packet: {exc}")
            return
    else:
        signed_message = ct

    if verify(PQC_IMPLEMENTATION, PHARMA_PK, signed_message, sig):
        print("✅ ML-DSA-65 signature VERIFIED")
    else:
        print("❌ Signature invalid!")
        return

    # === Step 2: Recover AES key from gateway session_key (demo only) ===
    if "session_key" not in packet:
        print("❌ No session_key found in packet")
        return

    shared_secret = bytes.fromhex(packet["session_key"])
    aes_key = derive_aes(shared_secret)

    # === Step 3: Decrypt AES-GCM payload ===
    nonce, tag, ciphertext = ct[:16], ct[16:32], ct[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("🔓 AES-GCM decryption successful")
    except Exception as e:
        print("❌ Decryption failed:", e)
        return

    # === Step 4: Save recovered file ===
    output_path = os.path.join(OUTPUT_DIR, filename)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"💾 Recovered file saved to: {output_path}")
    print(f"📄 File type: {filetype or 'unknown'}")
    print(f"📦 Source: {source}")
    print(f"📏 Size: {round(len(plaintext)/1024, 1)} KB")

    # === Optional preview for text-like files ===
    preview_text_if_possible(filetype, plaintext)


if __name__ == "__main__":
    main()