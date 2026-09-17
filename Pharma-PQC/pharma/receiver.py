# Pharma-PQC/pharma/receiver.py

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pharma_receiver(payload, gateway_sk, hospital_pk):
    ct_kem = bytes.fromhex(payload["ct_kem"])
    nonce = bytes.fromhex(payload["nonce"])
    ct_aes = bytes.fromhex(payload["ct_aes"])
    sigma = bytes.fromhex(payload["sigma"])
    
    # 1. Verify ML-DSA signature over the ciphertext
    is_valid = ML_DSA_65.verify(hospital_pk, ct_aes, sigma)
    if not is_valid:
        raise ValueError("Signature verification failed! Data rejected.")
        
    # 2. Recover shared secret (typically done by gateway, passed to receiver)
    ss = ML_KEM_768.decaps(gateway_sk, ct_kem)
    
    # 3. Derive identical AES key using HKDF-SHA-256
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
    k_aes = hkdf.derive(ss)
    
    # 4. Decrypt original file
    aesgcm = AESGCM(k_aes)
    original_bytes = aesgcm.decrypt(nonce, ct_aes, None)
    
    return original_bytes