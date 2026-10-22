# Pharma-PQC/hospital/sender_v2.py

import os
import time
import json
import hashlib
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hospital_sender_v2(file_path, gateway_pk, hospital_sk, sequence_num=1):
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
    
    # Serialize metadata deterministically for hashing
    metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
    
    # 5. Compute M_digest = SHA-256(Metadata || Nonce || Timestamp || ct_aes)
    digest_input = metadata_bytes + aes_nonce + str(timestamp).encode() + ct_aes
    m_digest = hashlib.sha256(digest_input).digest()
    
    # 6. Native C ML-DSA Signature over the digest (NOT just the ciphertext)
    with oqs.Signature('ML-DSA-65') as signer:
        signer.secret_key = hospital_sk
        sigma_improved = signer.sign(m_digest)
    
    # 7. Assemble the final secured payload
    payload = {
        "metadata": metadata,
        "timestamp": timestamp,
        "sequence_num": sequence_num,
        "ct_kem": ct_kem.hex(),
        "aes_nonce": aes_nonce.hex(),
        "ct_aes": ct_aes.hex(),
        "sigma": sigma_improved.hex()
    }
    
    return payload