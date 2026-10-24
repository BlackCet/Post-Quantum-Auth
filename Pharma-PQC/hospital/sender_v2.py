# Pharma-PQC/hospital/sender_v2.py

import os
import time
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from payload_auth import packet_digest


def hospital_sender_v2(file_path, gateway_pk, hospital_sk, sequence_num=1):
    if (
        not isinstance(sequence_num, int)
        or isinstance(sequence_num, bool)
        or sequence_num < 1
    ):
        raise ValueError("sequence_num must be a positive integer")

    # 1. Read input file
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    
    # 2. Native C ML-KEM Encapsulation
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        ct_kem, ss = kem.encap_secret(gateway_pk)
    
    # 3. Derive AES key and Encrypt
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
    k_aes = hkdf.derive(ss)
    
    aesgcm = AESGCM(k_aes)
    aes_nonce = os.urandom(12)
    ct_aes = aesgcm.encrypt(aes_nonce, file_bytes, None)
    
    # 4. Construct Authenticated Header (Replay & Metadata Protection)
    timestamp = int(time.time())
    metadata = {
        "filename": os.path.basename(file_path), 
        "format": "raw",
        "source_id": "hospital_node_alpha"
    }
    
    payload = {
        "metadata": metadata,
        "timestamp": timestamp,
        "sequence_num": sequence_num,
        "ct_kem": ct_kem.hex(),
        "aes_nonce": aes_nonce.hex(),
        "ct_aes": ct_aes.hex(),
    }

    # Sign canonical packet data so the sequence and KEM ciphertext are bound too.
    with oqs.Signature("ML-DSA-65", secret_key=hospital_sk) as signer:
        payload["sigma"] = signer.sign(packet_digest(payload)).hex()

    return payload