# Pharma-PQC/benchmarking/benchmark.py

import os
import time
from glob import glob
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def run_benchmarks():
    # Updated relative path to match your terminal location
    data_dir = "data_generation" 
    test_files = glob(os.path.join(data_dir, "dataset_*"))
    
    if not test_files:
        print(f"No datasets found in {data_dir}! Run generate_data.py first.")
        return

    print("--- Generating Keys for Benchmark ---")
    gateway_pk, gateway_sk = ML_KEM_768.keygen()
    hospital_pk, hospital_sk = ML_DSA_65.keygen()

    print(f"\n{'File':<25} | {'Size (MB)':<10} | {'KEM (ms)':<10} | {'AES Enc (ms)':<15} | {'ML-DSA Sign (ms)':<20} | {'Total Latency (ms)':<20}")
    print("-" * 115)

    for file_path in test_files:
        filename = os.path.basename(file_path)
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        # Start end-to-end pipeline timer
        t_start_total = time.perf_counter()

        # 1. KEM Encapsulation
        t0 = time.perf_counter()
        ss, ct_kem = ML_KEM_768.encaps(gateway_pk)
        t_kem = (time.perf_counter() - t0) * 1000

        # HKDF
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
        k_aes = hkdf.derive(ss)
        aesgcm = AESGCM(k_aes)
        nonce = os.urandom(12)

        # 2. AES Encryption
        t0 = time.perf_counter()
        ct_aes = aesgcm.encrypt(nonce, file_bytes, None)
        t_enc = (time.perf_counter() - t0) * 1000

        # 3. ML-DSA Sign
        t0 = time.perf_counter()
        sigma = ML_DSA_65.sign(hospital_sk, ct_aes)
        t_sign = (time.perf_counter() - t0) * 1000

        # 4. ML-DSA Verify
        t0 = time.perf_counter()
        is_valid = ML_DSA_65.verify(hospital_pk, ct_aes, sigma)
        t_verify = (time.perf_counter() - t0) * 1000

        # 5. KEM Decapsulation
        t0 = time.perf_counter()
        ss_rec = ML_KEM_768.decaps(gateway_sk, ct_kem)
        t_kem_dec = (time.perf_counter() - t0) * 1000

        # 6. AES Decryption
        hkdf_rec = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
        k_aes_rec = hkdf_rec.derive(ss_rec)
        aesgcm_rec = AESGCM(k_aes_rec)
        
        t0 = time.perf_counter()
        aesgcm_rec.decrypt(nonce, ct_aes, None)
        t_dec = (time.perf_counter() - t0) * 1000

        # Stop end-to-end timer
        t_total = (time.perf_counter() - t_start_total) * 1000

        print(f"{filename:<25} | {size_mb:<10.2f} | {t_kem:<10.2f} | {t_enc:<15.2f} | {t_sign:<20.2f} | {t_total:<20.2f}")

if __name__ == "__main__":
    run_benchmarks()