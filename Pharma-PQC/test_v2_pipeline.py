# Pharma-PQC/test_v2_pipeline.py

import os
import time
import copy
import oqs
from hospital.sender_v2 import hospital_sender_v2
from pharma.receiver_v2 import pharma_receiver_v2

# Simulated Gateway Replay Cache
seen_packets = set()

def gateway_replay_check(payload):
    packet_id = f"{payload['metadata']['source_id']}_{payload['sequence_num']}_{payload['timestamp']}"
    
    # Check timestamp bound (e.g., reject packets older than 5 minutes)
    if time.time() - payload['timestamp'] > 300:
        raise ValueError("Gateway REJECT: Packet timestamp expired!")
        
    if packet_id in seen_packets:
        raise ValueError("Gateway REJECT: Duplicate sequence number detected (Replay Attack)!")
        
    seen_packets.add(packet_id)
    return True

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
    
    print("\n--- Test 1: Legitimate Transmission ---")
    gateway_replay_check(payload_v2)
    recovered = pharma_receiver_v2(payload_v2, gateway_sk, hospital_pk)
    print(f"SUCCESS: Data decrypted cleanly -> {recovered.decode()}")

    print("\n--- Test 2: Replay Attack (Resending same packet) ---")
    try:
        gateway_replay_check(payload_v2)
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

if __name__ == "__main__":
    run_v2_tests()