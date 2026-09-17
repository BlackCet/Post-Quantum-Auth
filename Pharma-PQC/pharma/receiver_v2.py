# Pharma-PQC/pharma/receiver_v2.py

import json
import hashlib
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pharma_receiver_v2(payload, gateway_sk, hospital_pk):
    metadata = payload["metadata"]
    timestamp = payload["timestamp"]
    ct_kem = bytes.fromhex(payload["ct_kem"])
    aes_nonce = bytes.fromhex(payload["aes_nonce"])
    ct_aes = bytes.fromhex(payload["ct_aes"])
    sigma = bytes.fromhex(payload["sigma"])

    # 1. Reconstruct M_digest for verification
    metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
    digest_input = metadata_bytes + aes_nonce + str(timestamp).encode() + ct_aes
    m_digest = hashlib.sha256(digest_input).digest()

    # 2. Native C ML-DSA Verification over the digest
    with oqs.Signature('ML-DSA-65') as verifier:
        is_valid = verifier.verify(m_digest, sigma, hospital_pk)
    
    if not is_valid:
        raise ValueError("V2 Signature verification failed! Metadata or payload tampered.")

    # 3. Native C ML-KEM Decapsulation
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        kem.secret_key = gateway_sk
        ss = kem.decap_secret(ct_kem)

    # 4. Derive AES key and Decrypt
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
    k_aes = hkdf.derive(ss)

    aesgcm = AESGCM(k_aes)
    original_bytes = aesgcm.decrypt(aes_nonce, ct_aes, None)

    return original_bytes