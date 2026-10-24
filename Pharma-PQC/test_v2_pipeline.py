# Pharma-PQC/test_v2_pipeline.py

import os
import copy
import oqs
from hospital.sender_v2 import hospital_sender_v2
from gateway.replay_guard import ReplayGuard
from pharma.receiver_v2 import pharma_receiver_v2

def run_v2_tests():
    print("--- Setting Up V2 Keys (liboqs) ---")
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        gateway_pk = kem.generate_keypair()
        gateway_sk = kem.secret_key
        
    with oqs.Signature('ML-DSA-65') as signer:
        hospital_pk = signer.generate_keypair()
        hospital_sk = signer.secret_key

    test_file = "Pharma-PQC/data_generation/test_file.txt"
    with open(test_file, "wb") as f:
        f.write(b"SECURE V2 PAYLOAD")

    print("\n--- Generating V2 Authenticated Payload ---")
    payload_v2 = hospital_sender_v2(test_file, gateway_pk, hospital_sk, sequence_num=1)
    replay_guard = ReplayGuard()
    
    print("\n--- Test 1: Legitimate Transmission ---")
    replay_guard.accept(payload_v2, hospital_pk)
    recovered = pharma_receiver_v2(payload_v2, gateway_sk, hospital_pk)
    print(f"SUCCESS: Data decrypted cleanly -> {recovered.decode()}")

    print("\n--- Test 2: Replay Attack (Resending same packet) ---")
    try:
        replay_guard.accept(payload_v2, hospital_pk)
        print("FAIL: Gateway allowed a replay!")
    except ValueError as e:
        print(f"SUCCESS: {e}")

    print("\n--- Test 3: Metadata Spoofing (The Baseline Flaw) ---")
    tampered_metadata_payload = copy.deepcopy(payload_v2)
    tampered_metadata_payload["metadata"]["filename"] = "malicious.exe"
    try:
        pharma_receiver_v2(tampered_metadata_payload, gateway_sk, hospital_pk)
        print("FAIL: V2 receiver accepted spoofed metadata!")
    except ValueError as e:
        print(f"SUCCESS: V2 Receiver caught metadata tampering! -> {e}")

    print("\n--- Test 4: Sequence Number Tampering ---")
    tampered_sequence_payload = copy.deepcopy(payload_v2)
    tampered_sequence_payload["sequence_num"] += 1
    try:
        replay_guard.accept(tampered_sequence_payload, hospital_pk)
        print("FAIL: Gateway accepted an altered sequence number!")
    except ValueError as e:
        print(f"SUCCESS: Gateway caught sequence tampering! -> {e}")

if __name__ == "__main__":
    run_v2_tests()