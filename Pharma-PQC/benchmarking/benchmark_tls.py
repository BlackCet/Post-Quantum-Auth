import os
import time
import json
import ssl
import urllib.request
import hashlib
import base64
import oqs
from glob import glob
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def run_tls_benchmark():
    data_dir = "data_generation" 
    test_files = glob(os.path.join(data_dir, "dataset_*"))
    
    if not test_files:
        print(f"No datasets found in {data_dir}!")
        return

    print("--- Generating Keys for Benchmark ---")
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        gateway_pk = kem.generate_keypair()
        
    with oqs.Signature('ML-DSA-65') as signer:
        hospital_sk = signer.generate_keypair()
        hospital_sk = signer.export_secret_key()

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations("server_ecdsa.crt")
    client_context.check_hostname = False

    print(f"\n{'File':<25} | {'Size (MB)':<10} | {'KEM (ms)':<10} | {'AES Enc (ms)':<15} | {'ML-DSA Sign (ms)':<20} | {'Total Latency (ms)':<20}")
    print("-" * 115)

    for file_path in test_files:
        filename = os.path.basename(file_path)
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        t_start_total = time.perf_counter()

        # 1. Native C KEM
        t0 = time.perf_counter()
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        ct_kem, ss = kem.encap_secret(gateway_pk)
        t_kem = (time.perf_counter() - t0) * 1000

        # 2. AES Encryption
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
        k_aes = hkdf.derive(ss)
        aesgcm = AESGCM(k_aes)
        aes_nonce = os.urandom(12)
        t0 = time.perf_counter()
        ct_aes = aesgcm.encrypt(aes_nonce, file_bytes, None)
        t_enc = (time.perf_counter() - t0) * 1000

        # 3. Secure Digest & Sign
        timestamp = int(time.time())
        metadata = {"filename": filename, "format": "raw", "source_id": "hospital_node_alpha"}
        metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
        digest_input = metadata_bytes + aes_nonce + str(timestamp).encode() + ct_aes
        m_digest = hashlib.sha256(digest_input).digest()

        t0 = time.perf_counter()
        signer = oqs.Signature('ML-DSA-65')
        signer.secret_key = hospital_sk
        sigma_improved = signer.sign(m_digest)
        t_sign = (time.perf_counter() - t0) * 1000

        # 4. Construct Payload
        # 4. Construct Payload
        payload = {
            "metadata": metadata,
            "ct_kem": ct_kem.hex(),
            "aes_nonce": aes_nonce.hex(),
            "ciphertext": ct_aes.hex(),
            "signature": sigma_improved.hex(),
            "timestamp": timestamp
        }

        # 5. Network Transmission
        req = urllib.request.Request("https://localhost:5000/forward", method="POST")
        req.add_header('Content-Type', 'application/json')
        req_data = json.dumps(payload).encode('utf-8')

        try:
            with urllib.request.urlopen(req, data=req_data, context=client_context) as response:
                response.read()
            
            t_total = (time.perf_counter() - t_start_total) * 1000
            print(f"{filename:<25} | {size_mb:<10.2f} | {t_kem:<10.2f} | {t_enc:<15.2f} | {t_sign:<20.2f} | {t_total:<20.2f}")
        except Exception as e:
            print(f"{filename:<25} | {size_mb:<10.2f} | FAILED: {e}")

if __name__ == "__main__":
    run_tls_benchmark()