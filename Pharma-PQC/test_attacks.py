# Pharma-PQC/test_attacks.py

import os
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from hospital.sender import hospital_sender
from pharma.receiver import pharma_receiver
from attacker.attacker import Attacker

def run_attack_tests():
    print("--- Setting Up Keys & Payload ---")
    gateway_pk, gateway_sk = ML_KEM_768.keygen()
    hospital_pk, hospital_sk = ML_DSA_65.keygen()

    test_file = "Pharma-PQC/data_generation/test_file.txt"
    os.makedirs(os.path.dirname(test_file), exist_ok=True)
    with open(test_file, "wb") as f:
        f.write(b"CONFIDENTIAL PHARMACOVIGILANCE DATA REPORT")

    original_payload = hospital_sender(test_file, gateway_pk, hospital_sk)

    print("\n--- Test 1: Ciphertext Tampering Attack ---")
    tampered_payload = Attacker.tamper_ciphertext(original_payload)
    try:
        pharma_receiver(tampered_payload, gateway_sk, hospital_pk)
        print("FAIL: Tampered ciphertext was accepted!")
    except ValueError as e:
        print(f"SUCCESS: Tampering caught by signature check -> {e}")

    print("\n--- Test 2: Ciphertext Truncation Attack ---")
    truncated_payload = Attacker.truncate_payload(original_payload)
    try:
        pharma_receiver(truncated_payload, gateway_sk, hospital_pk)
        print("FAIL: Truncated payload was accepted!")
    except Exception as e:
        print(f"SUCCESS: Truncation caught -> {e}")

    print("\n--- Test 3: Metadata Manipulation (Baseline Weakness) ---")
    metadata_spoofed_payload = Attacker.tamper_metadata(original_payload)
    try:
        recovered = pharma_receiver(metadata_spoofed_payload, gateway_sk, hospital_pk)
        print(f"WARNING (Baseline Limitation Confirmed): Metadata was modified to "
              f"'{metadata_spoofed_payload['metadata']['filename']}', "
              f"yet signature check passed and data decrypted: {recovered.decode()}")
    except Exception as e:
        print(f"Unexpected rejection: {e}")

if __name__ == "__main__":
    run_attack_tests()